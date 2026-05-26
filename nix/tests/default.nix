{
  self,
  pkgs,
  lib,
  package,
}: let
  hfCaches = import ./huggingface.nix {
    inherit pkgs lib;
  };
  lfm2Model = "LiquidAI/LFM2-350M";
  lfm2HfHome = hfCaches.lfm2_350MCache;
  qwenModel = "Qwen/Qwen3-0.6B";
  qwenHfHome = hfCaches.qwen3_0_6BCache;
  # Combined HF cache so a single gateway can resolve config.json/tokenizer
  # for both models when routing via discovery.
  hfHomeBoth = pkgs.symlinkJoin {
    name = "hf-cache-multi";
    paths = [qwenHfHome lfm2HfHome];
  };
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
    networking.firewall = {
      enable = true;
      # mDNS service discovery (224.0.0.251). Required for the gateway's
      # discovery-mode lookup to find executors on the test bridge.
      allowedUDPPorts = [5353];
      # Linux's strict reverse-path filter drops multicast on bridged
      # interfaces; relax it so mDNS frames are accepted.
      checkReversePath = false;
    };
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
      # Open the iroh UDP listen port so peers can reach this executor.
      openFirewall = true;
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
  }: _: {
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
  }: _: {
    config = lib.mkMerge [
      baseNode
      {
        networking.firewall.allowedTCPPorts = [gatewayPort];
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

  # Discovery-mode counterpart: gateway has no pinned executor; routes via
  # mDNS+DHT. Pkarr/iroh logs are tightened so structured log fields stay
  # legible in the journal.
  mkGatewayNodeDiscovery = {
    hfHome,
    cores ? 2,
    memorySize ? 4096,
    extraPackages ? [],
  }: _: {
    imports = [hellasModule];
    config = lib.mkMerge [
      baseNode
      {
        environment.systemPackages = extraPackages;
        services.hellas = {
          inherit package;
          environment = {
            HF_HOME = hfHome;
            RUST_LOG = "info,iroh=warn,iroh_relay=warn,pkarr=warn,iroh_dns=warn";
          };
          gateway = {
            enable = true;
            host = "0.0.0.0";
            port = gatewayPort;
            retries = 1;
            openFirewall = true;
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

  proxyPort = 18080;
  proxyRequest = pkgs.writeText "hellas-gateway-proxy-request.json" (builtins.toJSON {
    model = "proxy-model";
    input = "Return the proxy marker.";
    max_output_tokens = 8;
  });
  proxyUpstream = pkgs.writeText "hellas-responses-upstream.py" ''
    import json
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            self.send_error(404)

        def do_POST(self):
            if self.path != "/v1/responses":
                self.send_error(404)
                return
            if self.headers.get("authorization") != "Bearer proxy-secret":
                self.send_error(401)
                return

            length = int(self.headers.get("content-length", "0"))
            request = json.loads(self.rfile.read(length))
            body = {
                "id": "resp_mock",
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": request["model"],
                "output": [
                    {
                        "id": "msg_mock",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "proxied-ok",
                                "annotations": [],
                            }
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 1,
                    "output_tokens": 2,
                    "total_tokens": 3,
                },
            }
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *args):
            return

    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
  '';

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
      # HF_HOME is set system-wide so the gateway resolves the cached weights
      # without each invocation needing to thread it through.
      nodes.gateway = _: {
        config = lib.mkMerge [
          baseNode
          {
            environment.systemPackages = [pkgs.pi-coding-agent];
            environment.variables.HF_HOME = qwenHfHome;
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
        # Trailing args after `--` are forwarded to pi. HF_HOME is set on the
        # gateway node's `environment.variables` so the prebuilt cache is used
        # without network access.
        # `--pi-log` keeps pi's output in its own file so we can inspect each
        # process's stream separately (gateway -> /tmp/gateway.log,
        # pi -> /tmp/pi.log).
        (pi_status, _) = gateway.execute(
            f"${package}/bin/hellas-cli gateway"
            f" --host=127.0.0.1 --port=${toString gatewayPort}"
            f" --retries=1"
            f" --node-id {executor_node_id}"
            f" --node-addr ${executorAddr}:${toString executorPort}"
            f" --force-model ${qwenModel}"
            f" --pi --pi-api ${api} --pi-log /tmp/pi.log"
            f" -- -p --no-session --no-extensions --offline --verbose"
            f" 'Use the bash tool to run: echo ${marker}. Then relay exactly what it printed.'"
            f" > /tmp/gateway.log 2>&1"
        )

        # Always dump the transcripts into the build log; `nix log <drv>`
        # keeps them accessible whether the test passes or fails.
        print("==== gateway output (${suffix}) ====")
        print(gateway.succeed("cat /tmp/gateway.log"))
        print("==== pi output (${suffix}) ====")
        print(gateway.succeed("cat /tmp/pi.log"))
        print("==== executor journal (${suffix}) ====")
        print(executor.succeed("journalctl -u hellas.service --no-pager -o cat"))

        assert pi_status == 0, f"pi exited with status {pi_status}"
        gateway.succeed("grep -F ${marker} /tmp/pi.log")
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

  # Two executors (qwen + lfm2), one gateway in discovery mode, two pi
  # processes in parallel. Verifies that mDNS routing finds the right
  # executor for each requested model and that distinct requests produce
  # distinct receipt and commitment values in the gateway journal.
  gateway-multi-model = pkgs.testers.runNixOSTest {
    name = "hellas-gateway-multi-model";

    nodes.executor_qwen = mkExecutorNode {
      model = qwenModel;
      hfHome = qwenHfHome;
      cores = 4;
      memorySize = 12288;
    };
    nodes.executor_lfm2 = mkExecutorNode {
      model = lfm2Model;
      hfHome = lfm2HfHome;
      cores = 2;
      memorySize = 6144;
    };
    nodes.gateway = mkGatewayNodeDiscovery {
      hfHome = hfHomeBoth;
      cores = 2;
      memorySize = 4096;
      extraPackages = [pkgs.pi-coding-agent];
    };

    testScript = {nodes, ...}: let
      piExtension = pkgs.writeText "hellas-multi.js" ''
        export default function (pi) {
          pi.registerProvider("hellas", {
            baseUrl: "http://127.0.0.1:${toString gatewayPort}/v1",
            apiKey: "unused",
            api: "openai-completions",
            models: [
              {
                id: "${qwenModel}",
                name: "Qwen (Hellas)",
                reasoning: false,
                input: ["text"],
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
                contextWindow: 32768,
                maxTokens: 256,
              },
              {
                id: "${lfm2Model}",
                name: "LFM2 (Hellas)",
                reasoning: false,
                input: ["text"],
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
                contextWindow: 32768,
                maxTokens: 256,
              },
            ],
          });
        }
      '';
      qwenMarker = "qwen-marker-works";
      lfm2Marker = "lfm2-marker-works";
    in ''
      start_all()

      executor_qwen.wait_for_unit("hellas.service")
      executor_lfm2.wait_for_unit("hellas.service")
      gateway.wait_for_unit("multi-user.target")

      gateway.wait_for_unit("hellas-gateway.service")
      gateway.wait_for_open_port(${toString gatewayPort})

      # Two pi processes in parallel, one per model. Each does a one-shot
      # bash-tool round-trip with a model-specific marker; they share one
      # gateway and the gateway's discovery layer must route each request
      # to the executor that preloaded the matching model.
      gateway.succeed(
          "set +e; "
          "( pi -e ${piExtension} --provider hellas --model ${qwenModel}"
          "  -p --no-session --no-extensions --offline --verbose"
          "  'Use the bash tool to run: echo ${qwenMarker}. Then relay exactly what it printed.'"
          "  > /tmp/pi-qwen.log 2>&1 ; echo $? > /tmp/pi-qwen.status ) &"
          " ( pi -e ${piExtension} --provider hellas --model ${lfm2Model}"
          "   -p --no-session --no-extensions --offline --verbose"
          "   'Use the bash tool to run: echo ${lfm2Marker}. Then relay exactly what it printed.'"
          "   > /tmp/pi-lfm2.log 2>&1 ; echo $? > /tmp/pi-lfm2.status ) &"
          " wait"
      )

      # Forensic dumps before asserts.
      print("==== pi qwen ====")
      print(gateway.succeed("cat /tmp/pi-qwen.log"))
      print("==== pi lfm2 ====")
      print(gateway.succeed("cat /tmp/pi-lfm2.log"))
      print("==== gateway journal ====")
      journal = gateway.succeed("journalctl -u hellas-gateway.service --no-pager -o cat")
      print(journal)
      print("==== executor_qwen journal ====")
      print(executor_qwen.succeed("journalctl -u hellas.service --no-pager -o cat"))
      print("==== executor_lfm2 journal ====")
      print(executor_lfm2.succeed("journalctl -u hellas.service --no-pager -o cat"))

      qs = int(gateway.succeed("cat /tmp/pi-qwen.status").strip())
      ls = int(gateway.succeed("cat /tmp/pi-lfm2.status").strip())
      assert qs == 0, f"qwen pi exited {qs}"
      assert ls == 0, f"lfm2 pi exited {ls}"

      gateway.succeed("grep -F ${qwenMarker} /tmp/pi-qwen.log")
      gateway.succeed("grep -F ${lfm2Marker} /tmp/pi-lfm2.log")

      # Each successful request emits one info! line with both fields. With
      # two distinct requests we expect ≥ 2 distinct
      # receipt_cid and ≥ 2 distinct commitment values.
      import re
      receipts = set(re.findall(r"receipt_cid=(\S+)", journal))
      commits  = set(re.findall(r"commitment=(\S+)", journal)) - {""}
      assert len(receipts) >= 2, f"expected ≥2 receipt_cid, got {receipts}"
      assert len(commits)  >= 2, f"expected ≥2 commitment, got {commits}"
    '';
  };

  gateway-proxy-responses = pkgs.testers.runNixOSTest {
    name = "hellas-gateway-proxy-responses";

    nodes.gateway = _: {
      imports = [hellasModule];
      config = lib.mkMerge [
        baseNode
        {
          services.hellas = {
            inherit package;
            environment = {
              OPENAI_API_KEY = "proxy-secret";
              RUST_LOG = "info";
            };
            gateway = {
              enable = true;
              host = "0.0.0.0";
              port = gatewayPort;
              responsesBackend = "proxy";
              responsesProxyUrl = "http://127.0.0.1:${toString proxyPort}/v1/responses";
              responsesProxyApiKeyEnv = "OPENAI_API_KEY";
              openFirewall = true;
            };
          };
          virtualisation.cores = 1;
          virtualisation.memorySize = 2048;
        }
      ];
    };

    nodes.client = clientNode;

    testScript = {nodes, ...}: let
      gatewayAddr = (lib.head nodes.gateway.networking.interfaces.eth1.ipv4.addresses).address;
    in ''
      start_all()
      gateway.wait_for_unit("multi-user.target")
      client.wait_for_unit("multi-user.target")

      gateway.succeed("${pkgs.python3}/bin/python ${proxyUpstream} ${toString proxyPort} > /tmp/responses-upstream.log 2>&1 &")
      gateway.wait_until_succeeds("curl -sf http://127.0.0.1:${toString proxyPort}/health")
      gateway.wait_for_unit("hellas-gateway.service")
      gateway.wait_for_open_port(${toString gatewayPort})

      client.succeed(
          "curl -sf http://${gatewayAddr}:${toString gatewayPort}/v1/responses -H 'content-type: application/json' --data @${proxyRequest} > /tmp/proxy-response.json"
      )
      client.succeed(
          "${pkgs.jq}/bin/jq -e '.model == \"proxy-model\" and .output[0].content[0].text == \"proxied-ok\" and .usage.total_tokens == 3' /tmp/proxy-response.json"
      )

      client.copy_from_vm("/tmp/proxy-response.json", "hellas-gateway-proxy-response.json")
    '';
  };
}
