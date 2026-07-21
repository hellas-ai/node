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
  chainSettlementMaker = "21tzoXVq7aGx61bNRTPDVn9hJhszdDA4CPcp9LYZL8ffT";
  chainSettlementTaker = "236h7pukvqi6u8ADu53erbWyLYXNyNEuB9BRNMXtVKUfZ";
  chainSettlementNative = "jesTu2BpszP8DKSoi1R5G6ggjHrsrVnboLdx6V47vkoR";

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

  chainValidatorFollowerPrelude =
    {
      homePrefix,
      validatorLog,
      followerLog,
      allocations,
      validatorSeed,
      startPort,
      metricsPort,
      followerPartitionPrefix,
    }:
    let
      allocationArgs = lib.concatMapStringsSep " " (
        allocation: "--genesis-allocation ${allocation}"
      ) allocations;
    in
    ''
      import time

      cli = "${validatorPackage}/bin/hellas-cli"
      rpc = "ws://127.0.0.1:${toString chainRpcPort}"
      home = "HOME=${homePrefix}/client-home"
      validator_log = "${validatorLog}"
      follower_log = "${followerLog}"

      def parse_fields(output):
          fields = {}
          for line in output.splitlines():
              parts = line.split(" ", 1)
              if len(parts) == 2:
                  fields[parts[0]] = parts[1]
          return fields

      def latest_block():
          output = machine.succeed(f"{home} {cli} chain query --rpc {rpc} latest-block")
          fields = parse_fields(output)
          assert "height" in fields and int(fields["height"]) > 0, output
          assert "payload" in fields, output
          return fields

      def follower_height():
          output = machine.succeed(f"cat {follower_log} || true")
          heights = []
          for line in output.splitlines():
              parts = line.split()
              if len(parts) == 3 and parts[0] == "height" and parts[2] in ["Applied", "Duplicate"]:
                  heights.append(int(parts[1]))
          return max(heights) if heights else 0

      def follower_activity_events():
          output = machine.succeed(f"cat {follower_log} || true")
          return sum(1 for line in output.splitlines() if line.startswith("activity finalization "))

      def wait_for_follower_stream_ready():
          deadline = time.time() + 60
          while time.time() < deadline:
              output = machine.succeed(f"cat {follower_log} || true")
              if "activity stream subscribed" in output:
                  return
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(
              f"follower did not subscribe to activity stream\n"
              f"follower:\n{follower}\nvalidator:\n{validator}"
          )

      start_all()
      machine.succeed(
          "mkdir -p ${homePrefix}/validator-home ${homePrefix}/client-home "
          "${homePrefix}/follower-home ${homePrefix}/follower-store"
      )
      machine.succeed(
          f"HOME=${homePrefix}/validator-home {cli} chain validator config "
          "-n 1 --seed ${toString validatorSeed} --start-port ${toString startPort} "
          "--ws-bind 127.0.0.1:${toString chainRpcPort} "
          "--metrics-port ${toString metricsPort} ${allocationArgs} "
          "> ${homePrefix}/validator.toml"
      )
      machine.succeed(
          f"{cli} chain validator check-config --config ${homePrefix}/validator.toml | grep -Fx ok"
      )
      machine.succeed(
          f"HOME=${homePrefix}/validator-home RUST_LOG=info {cli} chain validator run "
          f"--config ${homePrefix}/validator.toml "
          f"> {validator_log} 2>&1 & echo $! > ${homePrefix}/validator.pid"
      )
      try:
          machine.wait_for_open_port(${toString chainRpcPort})
      except Exception:
          print(machine.succeed(f"cat {validator_log} || true"))
          raise
      machine.succeed(
          f"HOME=${homePrefix}/follower-home RUST_LOG=info {cli} chain indexer follow "
          f"--rpc {rpc} --storage-dir ${homePrefix}/follower-store "
          "--partition-prefix ${followerPartitionPrefix} "
          f"> {follower_log} 2>&1 & echo $! > ${homePrefix}/follower.pid"
      )
      machine.wait_until_succeeds(
          f"{home} {cli} chain query --rpc {rpc} latest-block "
          f"> ${homePrefix}/latest.log && grep -Eq '^height [1-9][0-9]*$' ${homePrefix}/latest.log"
      )
      wait_for_follower_stream_ready()
    '';
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
            assuranceCodec = "tpm2.quote.v1";
            assurancePolicy = "0000000000000000000000000000000000000000000000000000000000000000";
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
      ${chainValidatorFollowerPrelude {
        homePrefix = "/tmp/chain-e2e";
        validatorLog = "/tmp/chain-e2e/validator.log";
        followerLog = "/tmp/chain-e2e/follower.log";
        allocations = [ "${chainOwner}:424242" ];
        validatorSeed = 7;
        startPort = 31200;
        metricsPort = 39200;
        followerPartitionPrefix = "chain-e2e-follower";
      }}
      owner = "${chainOwner}"

      def wait_for_follower_stream(baseline, baseline_events):
          deadline = time.time() + 60
          while time.time() < deadline:
              remote = int(latest_block()["height"])
              local = follower_height()
              events = follower_activity_events()
              if remote > baseline and local > baseline and events > baseline_events:
                  return local
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(f"follower did not advance past {baseline}: remote={remote} local={local} events={events}\nfollower:\n{follower}\nvalidator:\n{validator}")

      baseline = follower_height()
      baseline_events = follower_activity_events()
      advanced = wait_for_follower_stream(baseline, baseline_events)
      print(f"follower advanced from {baseline} to {advanced}")

      latest = latest_block()
      height = int(latest["height"])
      payload = latest["payload"]

      by_height = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalized-block --height {height}")
      assert f"height {height}" in by_height.splitlines(), by_height
      assert f"payload {payload}" in by_height.splitlines(), by_height
      assert any(line.startswith("block ") for line in by_height.splitlines()), by_height

      by_payload = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalized-block --payload {payload}")
      assert f"height {height}" in by_payload.splitlines(), by_payload
      assert f"payload {payload}" in by_payload.splitlines(), by_payload

      finalization = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalization --payload {payload}").strip()
      assert len(finalization) > 64 and all(c in "0123456789abcdef" for c in finalization), finalization

      validators = machine.succeed(f"{home} {cli} chain query --rpc {rpc} validators")
      assert validators.strip(), validators

      coins = machine.succeed(f"{home} {cli} chain query --rpc {rpc} coins-by-owner --owner {owner}")
      coin_lines = [line for line in coins.splitlines() if line.endswith(" 424242")]
      assert len(coin_lines) == 1, coins

      machine.succeed("kill $(cat /tmp/chain-e2e/follower.pid) $(cat /tmp/chain-e2e/validator.pid)")
    '';
  };

  chain-edge-settlement = pkgs.testers.runNixOSTest {
    name = "hellas-chain-edge-settlement";
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
      ${chainValidatorFollowerPrelude {
        homePrefix = "/tmp/chain-settlement";
        validatorLog = "/tmp/chain-settlement/validator.log";
        followerLog = "/tmp/chain-settlement/follower.log";
        allocations = [
          "${chainSettlementMaker}:100"
          "${chainSettlementTaker}:100"
        ];
        validatorSeed = 17;
        startPort = 31300;
        metricsPort = 39300;
        followerPartitionPrefix = "chain-settlement-follower";
      }}
      import re

      maker = "${chainSettlementMaker}"
      taker = "${chainSettlementTaker}"
      native = "${chainSettlementNative}"

      def coin_map(owner):
          output = machine.succeed(f"{home} {cli} chain query --rpc {rpc} coins-by-owner --owner {owner}")
          coins = {}
          for line in output.splitlines():
              parts = line.split()
              if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]) and parts[1].isdigit():
                  coins[parts[0]] = int(parts[1])
          return coins, output

      def wait_coin(owner, value):
          deadline = time.time() + 90
          while time.time() < deadline:
              coins, output = coin_map(owner)
              matches = [object_id for object_id, amount in coins.items() if amount == value]
              if len(matches) == 1:
                  return matches[0]
              time.sleep(1)
          raise Exception(f"owner {owner} did not acquire one {value}-value coin:\n{output}")

      def edge_output(edge_id):
          deadline = time.time() + 30
          while time.time() < deadline:
              payload = latest_block()["payload"]
              status, output = machine.execute(
                  f"{home} {cli} chain query --rpc {rpc} edge --object-id {edge_id} --payload {payload}"
              )
              if status == 0:
                  return output
              time.sleep(1)
          raise Exception(f"edge query did not reach an indexed snapshot:\n{output}")

      def wait_edge(edge_id, present):
          try:
              deadline = time.time() + 90
              while time.time() < deadline:
                  output = edge_output(edge_id)
                  found = any(line.startswith("value ") for line in output.splitlines())
                  absent = "none" in output.splitlines()
                  if (present and found) or (not present and absent):
                      return int(latest_block()["height"])
                  time.sleep(1)
              raise Exception(f"edge {edge_id} presence did not become {present}:\n{output}")
          except Exception as err:
              procs = machine.succeed("ps aux | grep -i hellas | grep -v grep || true")
              follower = machine.succeed(f"tail -40 {follower_log} || true")
              dmesg = machine.succeed("dmesg | tail -15 || true")
              validator = machine.succeed(f"tail -60 {validator_log} || true")
              raise Exception(
                  f"wait_edge({edge_id}, {present}) failed: {err}\n"
                  f"procs:\n{procs}\nfollower:\n{follower}\ndmesg:\n{dmesg}\nvalidator:\n{validator}"
              ) from err

      def follower_progress():
          return follower_height(), follower_activity_events()

      def wait_follower(baseline):
          deadline = time.time() + 90
          while time.time() < deadline:
              height = follower_height()
              events = follower_activity_events()
              if height > baseline[0] and events > baseline[1]:
                  return
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(
              f"follower did not advance after transition from height {baseline[0]} "
              f"and {baseline[1]} activity events\n"
              f"follower:\n{follower}\nvalidator:\n{validator}"
          )

      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000001\\n' "
          "> /tmp/chain-settlement/maker.key"
      )
      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000002\\n' "
          "> /tmp/chain-settlement/taker.key"
      )
      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000001\\n' "
          "> /tmp/chain-settlement/native.key"
      )
      # Scenario A: two genesis P-256 owners open with WebAuthn and mutually close.
      maker_genesis = wait_coin(maker, 100)
      taker_genesis = wait_coin(taker, 100)
      height = int(latest_block()["height"])
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn "
          f"--maker-funding {maker_genesis} --taker-funding {taker_genesis} "
          f"--protocol 1 --timeout {height + 1000000} "
          f"--timeout-payout {maker}:100 --timeout-payout {taker}:100"
      )
      edge_a = parse_fields(opened)["edge_id"]
      wait_edge(edge_a, True)
      wait_follower(baseline)
      edge_state = edge_output(edge_a)
      assert f"maker {maker}" in edge_state.splitlines(), edge_state
      assert f"taker {taker}" in edge_state.splitlines(), edge_state

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_a} --kind mutual "
          f"--payout {maker}:80 --payout {taker}:70 --payout {native}:50 "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn"
      )
      wait_edge(edge_a, False)
      wait_follower(baseline)
      maker_coin = wait_coin(maker, 80)
      assert wait_coin(taker, 70)
      native_coin = wait_coin(native, 50)

      # Scenario B: the untagged k1 payout funds an all-native edge and close.
      height = int(latest_block()["height"])
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/native.key --maker-auth native "
          "--taker-key /tmp/chain-settlement/native.key --taker-auth native "
          f"--maker-funding {native_coin} --protocol 2 --timeout {height + 1000000} "
          f"--timeout-payout {native}:50"
      )
      edge_b = parse_fields(opened)["edge_id"]
      wait_edge(edge_b, True)
      wait_follower(baseline)

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_b} --kind mutual "
          f"--payout {native}:50 "
          "--maker-key /tmp/chain-settlement/native.key --maker-auth native "
          "--taker-key /tmp/chain-settlement/native.key --taker-auth native"
      )
      wait_edge(edge_b, False)
      wait_follower(baseline)
      assert wait_coin(native, 50)

      # Scenario C: canonical Terms are persisted at Open and revealed at timeout.
      height = int(latest_block()["height"])
      timeout = height + 2000
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn "
          f"--maker-funding {maker_coin} --protocol 3 --timeout {timeout} "
          f"--timeout-payout {maker}:80 --terms-out /tmp/chain-settlement/timeout.terms"
      )
      edge_c = parse_fields(opened)["edge_id"]
      wait_edge(edge_c, True)
      wait_follower(baseline)
      while int(latest_block()["height"]) < timeout:
          time.sleep(1)

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_c} --kind timeout "
          f"--payout {maker}:80 --terms-file /tmp/chain-settlement/timeout.terms"
      )
      wait_edge(edge_c, False)
      wait_follower(baseline)
      assert wait_coin(maker, 80)

      machine.succeed(
          "kill $(cat /tmp/chain-settlement/follower.pid) $(cat /tmp/chain-settlement/validator.pid)"
      )
    '';
  };
}
