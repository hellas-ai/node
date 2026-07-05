{
  self,
  pkgs,
  lib,
  package,
  validatorPackage,
}:
let
  inherit (pkgs.hellasLib) executorPort;
  hellasModule = import ../modules/nixos.nix { inherit self; };

  gatewayPort = 8080;
  chainRpcPort = 31246;
  chainOwner = "wic3EQ9UxhwPSctsVsqdK9fpqivx6bMLpZZEyVD3MYeH";

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
in
{
  discovery-monitor = pkgs.testers.runNixOSTest {
    name = "hellas-discovery-monitor";
    nodes.machine = _: {
      imports = [ hellasModule ];
      config = lib.mkMerge [
        (mkBaseNode package)
        {
          services.hellas = {
            enable = true;
            inherit package;
            port = executorPort;
            openFirewall = true;
            executePolicy = "skip";
            queueSize = 2;
            fetchMaxInFlight = 2;
            fetchQueueSize = 3;
            graffiti = "e2e-discovery";
          };
          virtualisation.cores = 2;
          virtualisation.memorySize = 2048;
        }
      ];
    };
    testScript = ''
      start_all()
      machine.wait_for_unit("hellas.service")

      machine.wait_until_succeeds(
          "${package}/bin/hellas-cli monitor --timeout-secs 5 > /tmp/hellas-monitor.log 2>&1"
          " && grep -q 'event=discovered service=node' /tmp/hellas-monitor.log"
          " && grep -q 'event=node-info' /tmp/hellas-monitor.log"
      )
      monitor_output = machine.succeed("cat /tmp/hellas-monitor.log")
      print(monitor_output)
      assert "graffiti=e2e-discovery" in monitor_output
    '';
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

  chain-validator-follower = pkgs.testers.runNixOSTest {
    name = "hellas-chain-validator-follower";
    nodes.machine = _: {
      config = lib.mkMerge [
        (mkBaseNode validatorPackage)
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 2048;
        }
      ];
    };
    testScript = ''
      import time

      cli = "${validatorPackage}/bin/hellas-cli"
      rpc = "ws://127.0.0.1:${toString chainRpcPort}"
      owner = "${chainOwner}"

      def parse_fields(output):
          fields = {}
          for line in output.splitlines():
              parts = line.split(" ", 1)
              if len(parts) == 2:
                  fields[parts[0]] = parts[1]
          return fields

      def latest_block():
          output = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} latest-block")
          fields = parse_fields(output)
          assert "height" in fields and int(fields["height"]) > 0, output
          assert "payload" in fields, output
          return fields

      def follower_height():
          output = machine.succeed("cat /tmp/chain-e2e/follower.log || true")
          heights = []
          for line in output.splitlines():
              parts = line.split()
              if len(parts) == 3 and parts[0] == "height" and parts[2] in ["Applied", "Duplicate"]:
                  heights.append(int(parts[1]))
          return max(heights) if heights else 0

      def follower_activity_events():
          output = machine.succeed("cat /tmp/chain-e2e/follower.log || true")
          return sum(1 for line in output.splitlines() if line.startswith("activity finalization "))

      def wait_for_follower_stream_ready():
          deadline = time.time() + 60
          while time.time() < deadline:
              output = machine.succeed("cat /tmp/chain-e2e/follower.log || true")
              if "activity stream subscribed" in output:
                  return
              time.sleep(1)
          follower = machine.succeed("cat /tmp/chain-e2e/follower.log || true")
          validator = machine.succeed("cat /tmp/chain-e2e/validator.log || true")
          raise Exception(f"follower did not subscribe to activity stream\nfollower:\n{follower}\nvalidator:\n{validator}")

      def wait_for_follower_stream(baseline, baseline_events):
          deadline = time.time() + 60
          while time.time() < deadline:
              remote = int(latest_block()["height"])
              local = follower_height()
              events = follower_activity_events()
              if remote > baseline and local > baseline and events > baseline_events:
                  return local
              time.sleep(1)
          follower = machine.succeed("cat /tmp/chain-e2e/follower.log || true")
          validator = machine.succeed("cat /tmp/chain-e2e/validator.log || true")
          raise Exception(f"follower did not advance past {baseline}: remote={remote} local={local} events={events}\nfollower:\n{follower}\nvalidator:\n{validator}")

      start_all()

      machine.succeed("mkdir -p /tmp/chain-e2e/validator-home /tmp/chain-e2e/client-home /tmp/chain-e2e/follower-home /tmp/chain-e2e/follower-store")
      machine.succeed(
          f"HOME=/tmp/chain-e2e/validator-home {cli} chain validator config "
          "-n 1 --seed 7 --start-port 31200 "
          "--ws-bind 127.0.0.1:${toString chainRpcPort} "
          "--metrics-port 39200 "
          f"--genesis-allocation {owner}:424242 "
          "> /tmp/chain-e2e/validator.toml"
      )
      machine.succeed(f"{cli} chain validator check-config --config /tmp/chain-e2e/validator.toml | grep -Fx ok")
      machine.succeed(
          f"HOME=/tmp/chain-e2e/validator-home RUST_LOG=info {cli} chain validator run "
          "--config /tmp/chain-e2e/validator.toml "
          "> /tmp/chain-e2e/validator.log 2>&1 & echo $! > /tmp/chain-e2e/validator.pid"
      )
      machine.wait_for_open_port(${toString chainRpcPort})
      machine.succeed(
          f"HOME=/tmp/chain-e2e/follower-home RUST_LOG=info {cli} chain indexer follow "
          f"--rpc {rpc} --storage-dir /tmp/chain-e2e/follower-store "
          "--partition-prefix chain-e2e-follower "
          "> /tmp/chain-e2e/follower.log 2>&1 & echo $! > /tmp/chain-e2e/follower.pid"
      )
      machine.wait_until_succeeds(
          f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} latest-block "
          "> /tmp/chain-e2e/latest.log && grep -Eq '^height [1-9][0-9]*$' /tmp/chain-e2e/latest.log"
      )
      wait_for_follower_stream_ready()
      baseline = follower_height()
      baseline_events = follower_activity_events()
      advanced = wait_for_follower_stream(baseline, baseline_events)
      print(f"follower advanced from {baseline} to {advanced}")

      latest = latest_block()
      height = int(latest["height"])
      payload = latest["payload"]

      by_height = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} finalized-block --height {height}")
      assert f"height {height}" in by_height.splitlines(), by_height
      assert f"payload {payload}" in by_height.splitlines(), by_height
      assert any(line.startswith("block ") for line in by_height.splitlines()), by_height

      by_payload = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} finalized-block --payload {payload}")
      assert f"height {height}" in by_payload.splitlines(), by_payload
      assert f"payload {payload}" in by_payload.splitlines(), by_payload

      finalization = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} finalization --payload {payload}").strip()
      assert len(finalization) > 64 and all(c in "0123456789abcdef" for c in finalization), finalization

      validators = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} validators")
      assert validators.strip(), validators

      coins = machine.succeed(f"HOME=/tmp/chain-e2e/client-home {cli} chain query --rpc {rpc} coins-by-owner --owner {owner}")
      coin_lines = [line for line in coins.splitlines() if line.endswith(" 424242")]
      assert len(coin_lines) == 1, coins

      machine.succeed("kill $(cat /tmp/chain-e2e/follower.pid) $(cat /tmp/chain-e2e/validator.pid)")
    '';
  };
}
