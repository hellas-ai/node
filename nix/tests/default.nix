{
  self,
  pkgs,
  lib,
  package,
}: let
  testsLib = import ./lib.nix {
    inherit pkgs lib;
  };
  lfm2Model = "LiquidAI/LFM2-350M";
  lfm2HfHome = testsLib.lfm2_350MCache;
  qwenModel = "Qwen/Qwen3-0.6B";
  qwenHfHome = testsLib.qwen3_0_6BCache;
  hellasModule = import ../modules/nixos.nix {inherit self;};
  executorPort = 31145;
  gatewayPort = 8080;

  # The NixOS module runs `hellas-cli serve` with the default identity path.
  # `HOME=/var/lib/hellas` + default `.hellas/identity` → this concrete path.
  executorIdentityPath = "/var/lib/hellas/.hellas/identity";

  commonPackages = with pkgs; [
    coreutils
    curl
    jq
    gnugrep
    package
  ];

  baseNode = {
    networking.firewall.enable = false;
    environment.systemPackages = commonPackages;
  };

  mkHellasNode = {
    model,
    hfHome,
    executePolicy ? "skip",
    preload ? false,
  }: {
    services.hellas = {
      enable = true;
      inherit package;
      port = executorPort;
      downloadPolicy = "skip";
      inherit executePolicy;
      queueSize = 2;
      preloadWeights = lib.optionals preload [model];
      environment.HF_HOME = hfHome;
    };
  };

  mkExecutorNode = {
    model,
    hfHome,
    cores ? 2,
    memorySize ? 4096,
  }:
    _: {
      imports = [hellasModule];
      config = lib.mkMerge [
        baseNode
        (mkHellasNode {
          inherit model hfHome;
          executePolicy = "eager";
          preload = true;
        })
        {
          virtualisation.cores = cores;
          virtualisation.memorySize = memorySize;
        }
      ];
    };

  clientNode = _: {
    config = lib.mkMerge [
      baseNode
      {
        virtualisation.cores = 1;
        virtualisation.memorySize = 2048;
      }
    ];
  };

  gatewayLauncher = pkgs.writeShellScript "hellas-gateway-launcher" ''
    exec ${package}/bin/hellas-cli gateway \
      --host=0.0.0.0 \
      --port=${toString gatewayPort} \
      --retries=1 \
      --node-id "$(< /var/lib/hellas-gateway/node-id)" \
      --node-addr "$(< /var/lib/hellas-gateway/node-addr)"
  '';

  mkGatewayNode = {
    hfHome,
    cores ? 2,
    memorySize ? 3072,
  }:
    _: {
      config = lib.mkMerge [
        baseNode
        {
          systemd.services.hellas-gateway = {
            description = "Hellas gateway";
            after = ["network-online.target"];
            wants = ["network-online.target"];
            environment = {
              HF_HOME = hfHome;
              HOME = "/var/lib/hellas-gateway";
              RUST_LOG = "info";
            };
            serviceConfig = {
              DynamicUser = true;
              Restart = "on-failure";
              StateDirectory = "hellas-gateway";
              WorkingDirectory = "/var/lib/hellas-gateway";
              ExecStart = "${gatewayLauncher}";
            };
          };
          virtualisation.cores = cores;
          virtualisation.memorySize = memorySize;
        }
      ];
    };

  # Common Python lines to bring the executor + gateway pipeline up.
  # Defines `executor_node_id` and waits for the gateway HTTP port.
  bootGateway = executorAddr: ''
    executor.wait_for_unit("hellas.service")
    gateway.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")

    executor_node_id = executor.wait_until_succeeds(
        "${package}/bin/hellas-cli --identity ${executorIdentityPath} identity show-node-id"
    ).strip()

    gateway.wait_until_succeeds(
        f"${package}/bin/hellas-cli rpc {executor_node_id} --node-addr ${executorAddr}:${toString executorPort}"
    )

    gateway.succeed("install -d -m 0755 /var/lib/hellas-gateway")
    gateway.succeed(f"printf '%s\\n' {executor_node_id} > /var/lib/hellas-gateway/node-id")
    gateway.succeed("printf '%s\\n' '${executorAddr}:${toString executorPort}' > /var/lib/hellas-gateway/node-addr")
    gateway.succeed("systemctl start hellas-gateway.service")
    gateway.wait_for_unit("hellas-gateway.service")
    gateway.wait_for_open_port(${toString gatewayPort})
  '';

  gatewayRequest = pkgs.writeText "hellas-gateway-request.json" (builtins.toJSON {
    model = lfm2Model;
    messages = [
      {
        role = "user";
        content = "Reply with the single word hello.";
      }
    ];
    max_tokens = 8;
  });

  # Drives the gateway through pi-coding-agent and verifies the full agentic
  # loop. The model must call the bash tool to read a file whose contents it
  # could not otherwise know, then surface those contents in its final answer.
  # Captured artifacts (always, even on failure): pi stdout, executor journal,
  # gateway journal — named with the test suffix so both runs can coexist.
  mkToolUseTest = {
    suffix,
    api,
    baseUrlPath,
  }:
    pkgs.testers.runNixOSTest {
      name = "hellas-gateway-tool-use-${suffix}";

      nodes.executor = mkExecutorNode {
        model = qwenModel;
        hfHome = qwenHfHome;
        cores = 4;
        # Qwen3-0.6B f32 weights + catgrad runtime + KV cache + DHT overhead.
        # Observed OOM kernel panic at 6 GB AND 8 GB (DHT thread alloc).
        memorySize = 12288;
      };
      nodes.gateway = mkGatewayNode {hfHome = qwenHfHome;};
      nodes.client = _: {
        config = lib.mkMerge [
          baseNode
          {
            environment.systemPackages = [pkgs.pi-coding-agent];
            virtualisation.cores = 2;
            virtualisation.memorySize = 2048;
          }
        ];
      };

      testScript = {nodes, ...}: let
        executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
        gatewayAddr = (lib.head nodes.gateway.networking.interfaces.eth1.ipv4.addresses).address;
        piExtension = pkgs.writeText "hellas-pi-extension-${suffix}.js" ''
          export default function (pi) {
            pi.registerProvider("hellas", {
              baseUrl: "http://${gatewayAddr}:${toString gatewayPort}${baseUrlPath}",
              apiKey: "unused",
              api: "${api}",
              models: [{
                id: "${qwenModel}",
                name: "Qwen3 0.6B (Hellas)",
                reasoning: false,
                input: ["text"],
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
                contextWindow: 32768,
                maxTokens: 1024,
              }],
            });
          }
        '';
        marker = "hellas-tool-loop-works";
      in ''
        start_all()
        ${bootGateway executorAddr}

        # The prompt asks the model to run a specific bash command and relay
        # exactly what it printed — the bash tool is the only way to surface
        # the marker, and pass-through phrasing keeps small models on-rails.
        # Run pi without raising on non-zero exit so we still capture logs below.
        (pi_status, _) = client.execute(
            "pi -e ${piExtension} --provider hellas --model ${qwenModel}"
            " -p --no-session --no-extensions --offline --verbose"
            " 'Use the bash tool to run: echo ${marker}. Then relay exactly what it printed.'"
            " > /tmp/pi-out.txt 2>&1"
        )

        # Always dump the transcripts into the build log; `nix log <drv>`
        # keeps them accessible whether the test passes or fails.
        print("==== pi output (${suffix}) ====")
        print(client.succeed("cat /tmp/pi-out.txt"))
        print("==== executor journal (${suffix}) ====")
        print(executor.succeed("journalctl -u hellas.service --no-pager -o cat"))
        print("==== gateway journal (${suffix}) ====")
        print(gateway.succeed("journalctl -u hellas-gateway.service --no-pager -o cat"))

        assert pi_status == 0, f"pi exited with status {pi_status}"
        client.succeed("grep -F ${marker} /tmp/pi-out.txt")
      '';
    };
in {
  execute-direct = pkgs.testers.runNixOSTest {
    name = "hellas-execute-direct";

    nodes.executor = mkExecutorNode {
      model = lfm2Model;
      hfHome = lfm2HfHome;
    };
    nodes.client = clientNode;

    testScript = {nodes, ...}: let
      executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
    in ''
      start_all()

      executor.wait_for_unit("hellas.service")
      client.wait_for_unit("multi-user.target")

      executor_node_id = executor.wait_until_succeeds(
          "${package}/bin/hellas-cli --identity ${executorIdentityPath} identity show-node-id"
      ).strip()

      client.wait_until_succeeds(
          f"${package}/bin/hellas-cli rpc {executor_node_id} --node-addr ${executorAddr}:${toString executorPort}"
      )

      client.succeed(
          f"HF_HOME=${lfm2HfHome} timeout 300 ${package}/bin/hellas-cli llm {executor_node_id} --node-addr ${executorAddr}:${toString executorPort} --model=${lfm2Model} --prompt='Reply with the single word hello.' --max-seq 8 > /tmp/execute.out 2> /tmp/execute.err"
      )
      client.succeed("test -s /tmp/execute.out")

      client.copy_from_vm("/tmp/execute.out", "hellas-execute.out")
      client.copy_from_vm("/tmp/execute.err", "hellas-execute.err")
    '';
  };

  gateway-direct = pkgs.testers.runNixOSTest {
    name = "hellas-gateway-direct";

    nodes.executor = mkExecutorNode {
      model = lfm2Model;
      hfHome = lfm2HfHome;
    };
    nodes.gateway = mkGatewayNode {hfHome = lfm2HfHome;};
    nodes.client = clientNode;

    testScript = {nodes, ...}: let
      executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
      gatewayAddr = (lib.head nodes.gateway.networking.interfaces.eth1.ipv4.addresses).address;
    in ''
      start_all()
      ${bootGateway executorAddr}

      client.succeed(
          "curl -sf http://${gatewayAddr}:${toString gatewayPort}/v1/chat/completions -H 'content-type: application/json' --data @${gatewayRequest} > /tmp/gateway-response.json"
      )
      client.succeed(
          "${pkgs.jq}/bin/jq -e '.model == \"${lfm2Model}\" and (.choices[0].message.content | strings | length > 0)' /tmp/gateway-response.json"
      )

      client.copy_from_vm("/tmp/gateway-response.json", "hellas-gateway-response.json")
    '';
  };

  # Drives the gateway through pi-coding-agent and verifies the agentic loop:
  # the model must call the bash tool to read a file whose contents it could
  # not otherwise know, then surface those contents in its final answer.
  # Run once per supported wire format so we exercise both response shapes.
  gateway-tool-use-openai = mkToolUseTest {
    suffix = "openai";
    api = "openai-completions";
    # OpenAI SDK appends `/chat/completions` to baseUrl; we point it at our /v1 prefix.
    baseUrlPath = "/v1";
  };
  gateway-tool-use-anthropic = mkToolUseTest {
    suffix = "anthropic";
    api = "anthropic-messages";
    # Anthropic SDK appends `/v1/messages` itself; baseUrl stays at the host.
    baseUrlPath = "";
  };
}
