{
  self,
  pkgs,
  lib,
  package,
}:
let
  inherit (pkgs.hellasLib) executorPort;
  hellasModule = import ../modules/nixos.nix { inherit self; };

  gatewayPort = 8080;

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
}
