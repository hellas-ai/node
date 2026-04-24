{
  self,
  pkgs,
  lib,
  package,
}: let
  testsLib = import ./lib.nix {
    inherit pkgs lib;
  };
  model = "HuggingFaceTB/SmolLM2-135M-Instruct";
  hfHome = testsLib.smolLm2InstructCache;
  hellasModule = import ../modules/nixos.nix {inherit self;};
  executorPort = 31145;
  gatewayPort = 8080;

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
    executePolicy ? "skip",
    preload ? false,
    rustLog ? "info",
  }: {
    services.hellas = {
      enable = true;
      inherit package;
      port = executorPort;
      downloadPolicy = "skip";
      inherit executePolicy;
      queueSize = 2;
      preloadWeights = lib.optionals preload [model];
      environment = {
        HF_HOME = hfHome;
        RUST_LOG = rustLog;
      };
    };
  };

  gatewayLauncher = pkgs.writeShellScript "hellas-gateway-launcher" ''
    exec ${package}/bin/hellas-cli gateway \
      --host=0.0.0.0 \
      --port=${toString gatewayPort} \
      --retries=1 \
      --node-id "$(< /var/lib/hellas-gateway/node-id)" \
      --node-addr "$(< /var/lib/hellas-gateway/node-addr)"
  '';

  mkGatewayService = {
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
  };

  gatewayRequest = pkgs.writeText "hellas-gateway-request.json" (builtins.toJSON {
    model = model;
    messages = [
      {
        role = "user";
        content = "Reply with the single word hello.";
      }
    ];
    max_tokens = 8;
  });
in {
  execute-direct = pkgs.testers.runNixOSTest {
    name = "hellas-execute-direct";

    nodes.executor = {
      config,
      pkgs,
      ...
    }: {
      imports = [hellasModule];
      config = lib.mkMerge [
        baseNode
        (mkHellasNode {
          executePolicy = "eager";
          preload = true;
        })
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 4096;
        }
      ];
    };

    nodes.client = {
      config,
      pkgs,
      ...
    }: {
      config = lib.mkMerge [
        baseNode
        {
          virtualisation.cores = 1;
          virtualisation.memorySize = 2048;
        }
      ];
    };

    testScript = {nodes, ...}: let
      executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
    in ''
      start_all()

      executor.wait_for_unit("hellas.service")
      client.wait_for_unit("multi-user.target")

      executor.wait_until_succeeds(
          "journalctl -u hellas -b -o cat --no-pager | grep -q '^RPC server running\\.'"
      )
      executor_node_id = executor.succeed(
          "journalctl -u hellas -b -o cat --no-pager | sed -n 's/^Node ID:[[:space:]]*//p' | tail -1"
      ).strip()

      client.succeed(
          f"HF_HOME=${hfHome} timeout 300 ${package}/bin/hellas-cli llm {executor_node_id} --node-addr ${executorAddr}:${toString executorPort} --model=${model} --prompt='Reply with the single word hello.' --max-seq 8 > /tmp/execute.out 2> /tmp/execute.err"
      )
      client.succeed("test -s /tmp/execute.out")

      client.copy_from_vm("/tmp/execute.out", "hellas-execute.out")
      client.copy_from_vm("/tmp/execute.err", "hellas-execute.err")
    '';
  };

  # Same two-VM setup as execute-direct, but the client is given ONLY the
  # node-id — no --node-addr hint. Forces the CLI endpoint to resolve the
  # executor via its attached address_lookup stack (mDNS + Pkarr DHT + n0 DNS).
  # A passing test means discovery-only dialling works in a clean subnet;
  # a failure means we have a local reproducer for the iroh/swarm-discovery
  # or QUIC path-validation issue seen on real LAN.
  execute-discovery = pkgs.testers.runNixOSTest {
    name = "hellas-execute-discovery";

    nodes.executor = {
      config,
      pkgs,
      ...
    }: {
      imports = [hellasModule];
      config = lib.mkMerge [
        baseNode
        (mkHellasNode {
          executePolicy = "eager";
          preload = true;
          rustLog = "info,iroh::socket=trace,iroh::address_lookup::mdns=trace,swarm_discovery=debug,netwatch=debug";
        })
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 4096;
        }
      ];
    };

    nodes.client = {
      config,
      pkgs,
      ...
    }: {
      config = lib.mkMerge [
        baseNode
        {
          virtualisation.cores = 1;
          virtualisation.memorySize = 2048;
        }
      ];
    };

    testScript = ''
      start_all()

      executor.wait_for_unit("hellas.service")
      client.wait_for_unit("multi-user.target")

      executor.wait_until_succeeds(
          "journalctl -u hellas -b -o cat --no-pager | grep -q '^RPC server running\\.'"
      )
      executor_node_id = executor.succeed(
          "journalctl -u hellas -b -o cat --no-pager | sed -n 's/^Node ID:[[:space:]]*//p' | tail -1"
      ).strip()

      # Diagnostic: interfaces + local-addr iroh/netwatch state at launch.
      print("=== executor ip addr ===")
      print(executor.succeed("ip addr"))
      print("=== executor journal (first 400 lines) ===")
      print(executor.succeed("journalctl -u hellas -b -o cat --no-pager | head -400"))

      # Run the CLI without a node-addr hint. Capture output regardless of
      # success so we can inspect failures in the build log.
      status = client.execute(
          f"HF_HOME=${hfHome} RUST_LOG=hellas_cli=info,tonic_iroh_transport=debug,iroh::socket=trace,iroh::address_lookup::mdns=trace,swarm_discovery=debug,netwatch=debug timeout 300 ${package}/bin/hellas-cli llm {executor_node_id} --model=${model} --prompt='Reply with the single word hello.' --max-seq 8 > /tmp/execute.out 2> /tmp/execute.err"
      )

      tail = client.succeed("tail -400 /tmp/execute.err || true")
      print("=== client stderr (tail 400) ===")
      print(tail)
      exec_tail = executor.succeed("journalctl -u hellas -b -o cat --no-pager | tail -400")
      print("=== executor journal (tail 400) ===")
      print(exec_tail)

      assert status == 0, f"hellas-cli exited with status {status}"
      client.succeed("test -s /tmp/execute.out")
    '';
  };

  gateway-direct = pkgs.testers.runNixOSTest {
    name = "hellas-gateway-direct";

    nodes.executor = {
      config,
      pkgs,
      ...
    }: {
      imports = [hellasModule];
      config = lib.mkMerge [
        baseNode
        (mkHellasNode {
          executePolicy = "eager";
          preload = true;
        })
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 4096;
        }
      ];
    };

    nodes.gateway = {
      config,
      pkgs,
      ...
    }: {
      config = lib.mkMerge [
        baseNode
        mkGatewayService
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 3072;
        }
      ];
    };

    nodes.client = {
      config,
      pkgs,
      ...
    }: {
      config = lib.mkMerge [
        baseNode
        {
          virtualisation.cores = 1;
          virtualisation.memorySize = 2048;
        }
      ];
    };

    testScript = {nodes, ...}: let
      executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
      gatewayAddr = (lib.head nodes.gateway.networking.interfaces.eth1.ipv4.addresses).address;
    in ''
      start_all()

      executor.wait_for_unit("hellas.service")
      gateway.wait_for_unit("multi-user.target")
      client.wait_for_unit("multi-user.target")

      executor.wait_until_succeeds(
          "journalctl -u hellas -b -o cat --no-pager | grep -q '^RPC server running\\.'"
      )
      executor_node_id = executor.succeed(
          "journalctl -u hellas -b -o cat --no-pager | sed -n 's/^Node ID:[[:space:]]*//p' | tail -1"
      ).strip()

      gateway.succeed("install -d -m 0755 /var/lib/hellas-gateway")
      gateway.succeed(f"printf '%s\\n' {executor_node_id} > /var/lib/hellas-gateway/node-id")
      gateway.succeed("printf '%s\\n' '${executorAddr}:${toString executorPort}' > /var/lib/hellas-gateway/node-addr")
      gateway.succeed("systemctl start hellas-gateway.service")
      gateway.wait_for_unit("hellas-gateway.service")
      gateway.wait_for_open_port(${toString gatewayPort})

      client.succeed(
          "curl -sf http://${gatewayAddr}:${toString gatewayPort}/v1/chat/completions -H 'content-type: application/json' --data @${gatewayRequest} > /tmp/gateway-response.json"
      )
      client.succeed(
          "${pkgs.jq}/bin/jq -e '.model == \"${model}\" and (.choices[0].message.content | strings | length > 0)' /tmp/gateway-response.json"
      )

      client.copy_from_vm("/tmp/gateway-response.json", "hellas-gateway-response.json")
    '';
  };
}
