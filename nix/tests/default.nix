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
  # Uses the gateway's built-in `--pi` switch: hellas-cli writes the provider
  # extension itself and supervises the pi child, so no separate client node
  # or hand-written extension is needed.
  mkToolUseTest = {
    suffix,
    api,
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
      # Gateway node also runs pi (via `--pi`), so it needs pi-coding-agent.
      nodes.gateway = _: {
        config = lib.mkMerge [
          baseNode
          {
            environment.systemPackages = [pkgs.pi-coding-agent];
            virtualisation.cores = 2;
            virtualisation.memorySize = 3072;
          }
        ];
      };

      testScript = {nodes, ...}: let
        executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
        marker = "hellas-tool-loop-works";
      in ''
        start_all()
        executor.wait_for_unit("hellas.service")
        gateway.wait_for_unit("multi-user.target")

        executor_node_id = executor.wait_until_succeeds(
            "${package}/bin/hellas-cli --identity ${executorIdentityPath} identity show-node-id"
        ).strip()

        gateway.wait_until_succeeds(
            f"${package}/bin/hellas-cli rpc {executor_node_id} --node-addr ${executorAddr}:${toString executorPort}"
        )

        # Run gateway with --pi: gateway binds, spawns pi, exits when pi exits.
        # Trailing args after `--` are forwarded to pi.
        (pi_status, _) = gateway.execute(
            f"${package}/bin/hellas-cli gateway"
            f" --host=127.0.0.1 --port=${toString gatewayPort}"
            f" --retries=1"
            f" --node-id {executor_node_id}"
            f" --node-addr ${executorAddr}:${toString executorPort}"
            f" --force-model ${qwenModel}"
            f" --pi --pi-api ${api}"
            f" -- -p --no-session --no-extensions --offline --verbose"
            f" 'Use the bash tool to run: echo ${marker}. Then relay exactly what it printed.'"
            f" > /tmp/pi-out.txt 2>&1"
        )

        # Always dump the transcripts into the build log; `nix log <drv>`
        # keeps them accessible whether the test passes or fails.
        print("==== pi+gateway output (${suffix}) ====")
        print(gateway.succeed("cat /tmp/pi-out.txt"))
        print("==== executor journal (${suffix}) ====")
        print(executor.succeed("journalctl -u hellas.service --no-pager -o cat"))

        assert pi_status == 0, f"pi exited with status {pi_status}"
        gateway.succeed("grep -F ${marker} /tmp/pi-out.txt")
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
  };
  gateway-tool-use-anthropic = mkToolUseTest {
    suffix = "anthropic";
    api = "anthropic-messages";
  };
}
