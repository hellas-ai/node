{
  self,
  pkgs,
  lib,
  package,
  hellasRun,
}:
let
  inherit (pkgs.hellasLib) hf executorPort defaultStateDir;
  flavors = pkgs.hellasLib.apiFlavor;
  hellasModule = import ../modules/nixos.nix { inherit self; };

  gatewayPort = 8080;
  executorIdentityPath = "${defaultStateDir}/.hellas/identity";

  models = {
    lfm2_350m = {
      id = "LiquidAI/LFM2-350M";
      hfHome = hf.lfm2_350MCache;
      cores = 2;
      memorySize = 6144;
    };
    qwen3_0_6b = {
      id = "Qwen/Qwen3-0.6B";
      hfHome = hf.qwen3_0_6BCache;
      cores = 4;
      memorySize = 12288;
    };
  };

  mkPrompt =
    marker: proofPath:
    "Use the bash tool to run: echo ${marker} > ${proofPath}. Confirm in your reply once the file has been written.";

  responsesMock = pkgs.writeText "responses-mock.py" ''
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    def response_body(request, text):
        return {
            "id": "resp_mock",
            "object": "response",
            "created_at": 0,
            "model": request["model"],
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg_mock",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": text,
                }],
            }],
            "usage": {
                "input_tokens": 1,
                "output_tokens": 2,
                "total_tokens": 3,
            },
        }

    def sse_frame(name, data):
        encoded = json.dumps(data, separators=(",", ":"))
        return f"event: {name}\ndata: {encoded}\n\n".encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            assert self.path == "/v1/responses", self.path
            assert self.headers.get("authorization") == "Bearer proxy-secret"
            request = json.loads(body)
            if request.get("stream"):
                frames = [
                    sse_frame("response.output_item.added", {
                        "type": "response.output_item.added",
                        "item": {
                            "type": "message",
                            "id": "msg_mock",
                            "role": "assistant",
                            "status": "in_progress",
                            "content": [],
                        },
                    }),
                    sse_frame("response.output_text.delta", {
                        "type": "response.output_text.delta",
                        "item_id": "msg_mock",
                        "delta": "stream",
                    }),
                    sse_frame("response.output_text.delta", {
                        "type": "response.output_text.delta",
                        "item_id": "msg_mock",
                        "delta": "-proxied-ok",
                    }),
                    sse_frame("response.output_text.done", {
                        "type": "response.output_text.done",
                        "item_id": "msg_mock",
                        "text": "stream-proxied-ok",
                    }),
                    sse_frame("response.completed", {
                        "type": "response.completed",
                        "response": response_body(request, "stream-proxied-ok"),
                    }),
                ]
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                for frame in frames:
                    self.wfile.write(frame)
                    self.wfile.flush()
                return

            encoded = json.dumps(response_body(request, "proxied-ok")).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args):
            pass

    HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
  '';

  harnesses = {
    pi =
      {
        marker ? "hellas-tool-loop-works",
      }:
      {
        kind = "pi";
        inherit marker;
      };
  };

  topologies = {
    local = attrs: { kind = "local"; } // attrs;
    remote = attrs: { kind = "remote"; } // attrs;
    gateway = attrs: { kind = "gateway"; } // attrs;
  };

  mkBaseNode = hellasPackage: {
    networking.firewall = {
      enable = true;
      allowedUDPPorts = [ 5353 ];
      checkReversePath = false;
    };
    environment.systemPackages = with pkgs; [
      coreutils
      curl
      jq
      gnugrep
      hellasPackage
    ];
  };

  mkHellasNode =
    {
      hellasPackage,
      model,
      executePolicy ? "skip",
      preload ? false,
    }:
    {
      services.hellas = {
        enable = true;
        package = hellasPackage;
        port = executorPort;
        openFirewall = true;
        downloadPolicy = "skip";
        inherit executePolicy;
        queueSize = 2;
        preloadWeights = lib.optionals preload [ model.id ];
        environment.HF_HOME = model.hfHome;
      };
    };

  mkExecutorNode =
    {
      hellasPackage,
      model,
      cores ? model.cores,
      memorySize ? model.memorySize,
    }:
    _: {
      imports = [ hellasModule ];
      config = lib.mkMerge [
        (mkBaseNode hellasPackage)
        (mkHellasNode {
          inherit hellasPackage model;
          executePolicy = "eager";
          preload = true;
        })
        {
          virtualisation.cores = cores;
          virtualisation.memorySize = memorySize;
        }
      ];
    };

  mkGatewayNode =
    {
      hellasPackage,
      runner,
      hfHome,
      cores,
      memorySize,
      extraEnv ? { },
    }:
    _: {
      config = lib.mkMerge [
        (mkBaseNode hellasPackage)
        {
          environment.systemPackages = [ runner ];
          environment.variables = {
            HF_HOME = hfHome;
          }
          // extraEnv;
          virtualisation.cores = cores;
          virtualisation.memorySize = memorySize;
        }
      ];
    };

  mkHarnessCommand =
    harness:
    if harness.kind == "pi" then
      "pi -p --no-session --no-extensions --offline --verbose ${lib.escapeShellArg harness.prompt}"
    else
      throw "unsupported e2e harness: ${harness.kind}";

  normalizeAgent =
    index: agent:
    let
      agentName = agent.name or "agent-${toString index}";
      proofPath = agent.proofPath or "/tmp/${agentName}.proof";
    in
    agent
    // {
      apiFlavor = agent.apiFlavor or flavors.openai;
      name = agentName;
      logPath = agent.logPath or "/tmp/${agentName}.log";
      statusPath = agent.statusPath or "/tmp/${agentName}.status";
      inherit proofPath;
      harness = agent.harness // {
        prompt = mkPrompt agent.harness.marker proofPath;
      };
    };

  mkAgentScript =
    name: agents:
    let
      statusPaths = map (agent: agent.statusPath) agents;
      cleanupPaths = statusPaths ++ map (agent: agent.proofPath) agents;
      runAgents = lib.concatMapStringsSep "\n" (
        agent:
        let
          inherit (agent) apiFlavor harness;
        in
        ''
          (
            HELLAS_API=${lib.escapeShellArg apiFlavor} \
              HELLAS_MODEL=${lib.escapeShellArg agent.model.id} \
              ${mkHarnessCommand harness} > ${agent.logPath} 2>&1
            echo $? > ${agent.statusPath}
          ) &
        ''
      ) agents;
      statusChecks = lib.concatMapStringsSep "\n" (statusPath: ''
        status="$(cat ${statusPath} 2>/dev/null || echo 127)"
        if [ "$status" -ne 0 ]; then failed=1; fi
      '') statusPaths;
    in
    pkgs.writeShellScript "hellas-${name}-agents" ''
      set +e
      rm -f ${lib.concatStringsSep " " cleanupPaths}
      ${runAgents}
      wait
      failed=0
      ${statusChecks}
      exit "$failed"
    '';

  mkHfHome =
    name: agents:
    pkgs.symlinkJoin {
      name = "hf-cache-${name}";
      paths = map (agent: agent.model.hfHome) agents;
    };

  mkCaseAssertions =
    agents:
    lib.concatMapStringsSep "\n" (agent: ''
      print("==== ${agent.name} output ====")
      print(gateway.succeed("cat ${agent.logPath}"))
      assert int(gateway.succeed("cat ${agent.statusPath}").strip()) == 0, "${agent.name} exited nonzero"
      proof = gateway.succeed("cat ${agent.proofPath}").strip()
      assert "${agent.harness.marker}" in proof, (
          f"${agent.name}: proof file ${agent.proofPath} did not contain marker"
          f" '${agent.harness.marker}' (got {proof!r})"
      )
    '') agents;

  mkRunWrappedScript =
    {
      name,
      runner,
      agentScript,
      flags,
      agents,
      expectReceipts ? false,
    }:
    ''
      (run_status, _) = gateway.execute(
          "${runner}/bin/hellas-run"
          " --log-file=/tmp/gateway.log"
          " --host=127.0.0.1 --port=${toString gatewayPort}"
          " --retries=1"
          ${flags}
          " ${agentScript}"
          " > /tmp/hellas-run.log 2>&1"
      )

      print("==== hellas-run output (${name}) ====")
      print(gateway.succeed("cat /tmp/hellas-run.log"))
      print("==== gateway log (${name}) ====")
      journal = gateway.succeed("cat /tmp/gateway.log")
      print(journal)
      ${mkCaseAssertions agents}
      assert run_status == 0, f"hellas-run exited {run_status}"
      ${lib.optionalString expectReceipts ''
        import re
        receipts = set(re.findall(r"receipt=(\S+)", journal))
        commits = set(re.findall(r"provenance=Some\(([0-9a-fA-F]{64})\)", journal))
        assert len(receipts) >= ${toString (builtins.length agents)}, f"expected receipts, got {receipts}"
        assert len(commits) >= ${toString (builtins.length agents)}, f"expected commitments, got {commits}"
      ''}
    '';

  mkToolUseTest =
    {
      name,
      topology,
      model ? null,
      harness ? null,
      apiFlavor ? flavors.openai,
      agents ? null,
      hellasPackage ? package,
      runner ? hellasRun,
    }:
    let
      normalizedAgents = lib.imap0 normalizeAgent (
        if agents == null then
          [
            {
              inherit model harness apiFlavor;
              name = harness.kind or "agent";
            }
          ]
        else
          agents
      );
      primaryModel = (lib.head normalizedAgents).model;
      agentScript = mkAgentScript name normalizedAgents;
      gatewayHfHome =
        topology.hfHome
          or (if topology.kind == "gateway" then mkHfHome name normalizedAgents else primaryModel.hfHome);
      gatewayNode = mkGatewayNode {
        inherit hellasPackage runner;
        hfHome = gatewayHfHome;
        cores = topology.gatewayCores or (if topology.kind == "local" then primaryModel.cores else 2);
        memorySize =
          topology.gatewayMemorySize or (if topology.kind == "local" then primaryModel.memorySize else 3072);
        extraEnv = topology.gatewayEnv or { };
      };
      runLocal = mkRunWrappedScript {
        inherit name runner agentScript;
        agents = normalizedAgents;
        flags = ''
          " --local"
          " --force-model=${primaryModel.id}"
        '';
      };
    in
    pkgs.testers.runNixOSTest (
      {
        name = "hellas-${name}";
      }
      // (
        if topology.kind == "local" then
          {
            nodes.gateway = gatewayNode;
            testScript = ''
              start_all()
              gateway.wait_for_unit("multi-user.target")
              ${runLocal}
            '';
          }
        else if topology.kind == "remote" then
          let
            executorPackage = topology.executorPackage or hellasPackage;
          in
          {
            nodes = {
              executor = mkExecutorNode {
                hellasPackage = executorPackage;
                model = primaryModel;
                cores = topology.executorCores or primaryModel.cores;
                memorySize = topology.executorMemorySize or primaryModel.memorySize;
              };
              gateway = gatewayNode;
            };
            testScript =
              { nodes, ... }:
              let
                executorAddr = (lib.head nodes.executor.networking.interfaces.eth1.ipv4.addresses).address;
                runRemote = mkRunWrappedScript {
                  inherit name runner agentScript;
                  agents = normalizedAgents;
                  flags = ''
                    f" --node-id={executor_node_id}"
                    " --node-addr=${executorAddr}:${toString executorPort}"
                    " --force-model=${primaryModel.id}"
                  '';
                };
              in
              ''
                start_all()
                executor.wait_for_unit("hellas.service")
                gateway.wait_for_unit("multi-user.target")

                executor_node_id = executor.wait_until_succeeds(
                    "${executorPackage}/bin/hellas-cli --identity ${executorIdentityPath} identity show-node-id"
                ).strip()

                gateway.wait_until_succeeds(
                    f"${hellasPackage}/bin/hellas-cli rpc {executor_node_id} --node-addr ${executorAddr}:${toString executorPort}"
                )

                ${runRemote}
                print("==== executor journal (${name}) ====")
                print(executor.succeed("journalctl -u hellas.service --no-pager -o cat"))
              '';
          }
        else if topology.kind == "gateway" then
          let
            executorNodes = lib.mapAttrs (
              _nodeName: node:
              mkExecutorNode {
                hellasPackage = node.package or hellasPackage;
                inherit (node) model;
                cores = node.cores or node.model.cores;
                memorySize = node.memorySize or node.model.memorySize;
              }
            ) topology.executors;
            executorNames = lib.attrNames topology.executors;
            targetedAgents = builtins.filter (agent: agent ? executor) normalizedAgents;
            discoveryAgents = builtins.filter (agent: !(agent ? executor)) normalizedAgents;
            waitForExecutors = lib.concatMapStringsSep "\n" (
              nodeName: ''${nodeName}.wait_for_unit("hellas.service")''
            ) executorNames;
            printExecutorJournals = lib.concatMapStringsSep "\n" (nodeName: ''
              print("==== ${nodeName} journal (${name}) ====")
              print(${nodeName}.succeed("journalctl -u hellas.service --no-pager -o cat"))
            '') executorNames;
          in
          {
            nodes = executorNodes // {
              gateway = gatewayNode;
            };
            testScript =
              { nodes, ... }:
              let
                executorAddrs = lib.mapAttrs (
                  nodeName: _node: (lib.head nodes.${nodeName}.networking.interfaces.eth1.ipv4.addresses).address
                ) topology.executors;
                loadExecutorIds = lib.concatMapStringsSep "\n" (
                  nodeName:
                  let
                    node = topology.executors.${nodeName};
                    executorPackage = node.package or hellasPackage;
                  in
                  ''
                    ${nodeName}_node_id = ${nodeName}.wait_until_succeeds(
                        "${executorPackage}/bin/hellas-cli --identity ${executorIdentityPath} identity show-node-id"
                    ).strip()

                    gateway.wait_until_succeeds(
                        f"${hellasPackage}/bin/hellas-cli rpc {${nodeName}_node_id} --node-addr ${executorAddrs.${nodeName}}:${toString executorPort}"
                    )
                  ''
                ) executorNames;
                runTargetedGateway = lib.concatMapStringsSep "\n" (
                  agent:
                  let
                    nodeName = agent.executor;
                    agentScriptForTarget = mkAgentScript "${name}-${agent.name}" [ agent ];
                  in
                  mkRunWrappedScript {
                    name = "${name}-${agent.name}";
                    inherit runner;
                    agentScript = agentScriptForTarget;
                    agents = [ agent ];
                    expectReceipts = topology.expectReceipts or false;
                    flags = ''
                      f" --node-id={${nodeName}_node_id}"
                      " --node-addr=${executorAddrs.${nodeName}}:${toString executorPort}"
                      " --force-model=${agent.model.id}"
                    '';
                  }
                ) targetedAgents;
                runDiscoveryGateway = lib.optionalString (discoveryAgents != [ ]) (mkRunWrappedScript {
                  inherit name runner;
                  agentScript = mkAgentScript "${name}-discovery" discoveryAgents;
                  agents = discoveryAgents;
                  expectReceipts = topology.expectReceipts or false;
                  flags = "";
                });
              in
              ''
                start_all()
                ${waitForExecutors}
                gateway.wait_for_unit("multi-user.target")
                ${loadExecutorIds}
                ${runTargetedGateway}
                ${runDiscoveryGateway}
                ${printExecutorJournals}
              '';
          }
        else
          throw "unsupported e2e topology: ${topology.kind}"
      )
    );
in
{
  gateway-tool-use-local = mkToolUseTest {
    name = "gateway-tool-use-local";
    model = models.qwen3_0_6b;
    apiFlavor = flavors.openai;
    harness = harnesses.pi {
      marker = "hellas-local-tool-loop-works";
    };
    topology = topologies.local { };
  };

  gateway-tool-use-openai = mkToolUseTest {
    name = "gateway-tool-use-openai";
    model = models.qwen3_0_6b;
    apiFlavor = flavors.openai;
    harness = harnesses.pi { };
    topology = topologies.remote { };
  };

  gateway-tool-use-anthropic = mkToolUseTest {
    name = "gateway-tool-use-anthropic";
    model = models.qwen3_0_6b;
    apiFlavor = flavors.anthropic;
    harness = harnesses.pi { };
    topology = topologies.remote { };
  };

  gateway-multi-model = mkToolUseTest {
    name = "gateway-multi-model";
    topology = topologies.gateway {
      gatewayMemorySize = 4096;
      gatewayEnv.RUST_LOG = "info,iroh=warn,iroh_relay=warn,pkarr=warn,iroh_dns=warn";
      expectReceipts = true;
      executors = {
        executor_qwen.model = models.qwen3_0_6b;
        executor_lfm2.model = models.lfm2_350m;
      };
    };
    agents = [
      {
        name = "pi-qwen";
        executor = "executor_qwen";
        model = models.qwen3_0_6b;
        apiFlavor = flavors.openai;
        harness = harnesses.pi {
          marker = "qwen-marker-works";
        };
      }
      {
        name = "pi-lfm2";
        executor = "executor_lfm2";
        model = models.lfm2_350m;
        apiFlavor = flavors.openai;
        harness = harnesses.pi {
          marker = "lfm2-marker-works";
        };
      }
    ];
  };

  gateway-proxy-responses = pkgs.testers.runNixOSTest {
    name = "hellas-gateway-proxy-responses";
    nodes.gateway = _: {
      imports = [ hellasModule ];
      config = lib.mkMerge [
        (mkBaseNode package)
        {
          environment.systemPackages = [ pkgs.python3 ];
          services.hellas = {
            inherit package;
            environment.OPENAI_API_KEY = "proxy-secret";
            gateway = {
              enable = true;
              port = gatewayPort;
              responsesBackend = "proxy";
              responsesProxyUrl = "http://127.0.0.1:18080/v1/responses";
              responsesProxyApiKeyEnv = "OPENAI_API_KEY";
            };
          };
        }
      ];
    };
    testScript = ''
      start_all()

      gateway.succeed("python3 ${responsesMock} >/tmp/responses_mock.log 2>&1 &")
      gateway.wait_until_succeeds("curl -sS -o /dev/null -X POST -H 'content-type: application/json' -H 'authorization: Bearer proxy-secret' -d '{\"model\":\"probe\",\"input\":\"hi\"}' http://127.0.0.1:18080/v1/responses")
      gateway.wait_for_unit("hellas-gateway.service")
      gateway.wait_for_open_port(${toString gatewayPort})
      response = gateway.succeed("curl -sS -X POST -H 'content-type: application/json' -d '{\"model\":\"llama-local\",\"input\":\"hello\"}' http://127.0.0.1:${toString gatewayPort}/v1/responses")
      print(response)
      assert "proxied-ok" in response
      stream = gateway.succeed("curl -sS -N -X POST -H 'content-type: application/json' -d '{\"model\":\"llama-local\",\"input\":\"hello\",\"stream\":true}' http://127.0.0.1:${toString gatewayPort}/v1/responses")
      print(stream)
      assert "stream-proxied-ok" in stream
      assert "response.output_text.delta" in stream
      assert '"output_index":0' in stream
      assert '"content_index":0' in stream
    '';
  };
}
