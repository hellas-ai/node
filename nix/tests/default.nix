{
  self,
  pkgs,
  lib,
  server,
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
    server
  ];

  baseNode = {
    networking.firewall.enable = false;
    environment.systemPackages = commonPackages;
  };

  mkHellasNode = {
    executePolicy ? "skip",
    preload ? false,
  }: {
    services.hellas = {
      enable = true;
      package = server;
      port = executorPort;
      downloadPolicy = "skip";
      inherit executePolicy;
      queueSize = 2;
      preloadWeights = lib.optionals preload [model];
      environment = {
        HF_HOME = hfHome;
        RUST_LOG = "info";
      };
    };
  };

  gatewayLauncher = pkgs.writeShellScript "hellas-gateway-launcher" ''
    exec ${server}/bin/hellas-cli gateway \
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
          "journalctl -u hellas -b -o cat --no-pager | sed -n 's/^Node Address: //p' | tail -1"
      ).strip()

      client.succeed(
          f"HF_HOME=${hfHome} timeout 300 ${server}/bin/hellas-cli execute {executor_node_id} --node-addr ${executorAddr}:${toString executorPort} --model=${model} --prompt='Reply with the single word hello.' --max-seq 8 > /tmp/execute.out 2> /tmp/execute.err"
      )
      client.succeed("test -s /tmp/execute.out")

      client.copy_from_vm("/tmp/execute.out", "hellas-execute.out")
      client.copy_from_vm("/tmp/execute.err", "hellas-execute.err")
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
          "journalctl -u hellas -b -o cat --no-pager | sed -n 's/^Node Address: //p' | tail -1"
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
