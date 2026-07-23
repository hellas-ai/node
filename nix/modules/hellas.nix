{ self }:
rec {
  # The ordinary production CLI: local CPU execution and OTEL, without an
  # accelerator-specific backend. Accelerator builds remain explicit module
  # overrides.
  normalCliPackage = pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.cli-candle;

  # Pick the best available hellas CLI variant for the target system:
  #   Darwin         → cli-candle-metal
  #   Linux + cuda   → cli-candle-cuda  (requires `nixpkgs.config.cudaSupport = true`)
  #   otherwise      → cli-candle
  # Each step checks the package set for membership so a missing variant
  # falls through instead of erroring.
  pickCliPackage =
    pkgs:
    let
      pkgSet = self.packages.${pkgs.stdenv.hostPlatform.system};
      inherit (pkgs.stdenv.hostPlatform) isDarwin;
      cudaEnabled = pkgs.config.cudaSupport or false;
    in
    if isDarwin && pkgSet ? cli-candle-metal then
      pkgSet.cli-candle-metal
    else if cudaEnabled && pkgSet ? cli-candle-cuda then
      pkgSet.cli-candle-cuda
    else
      pkgSet.cli-candle;

  renderEnvironment = builtins.mapAttrs (_: toString);

  commonOptions =
    {
      lib,
      package,
      packageDescription,
    }:
    let
      inherit (lib) mkEnableOption mkOption types;
    in
    {
      enable = mkEnableOption "Hellas";
      package = mkOption {
        type = types.package;
        default = package;
        description = packageDescription;
      };
      environment = mkOption {
        type = types.attrsOf (
          types.oneOf [
            types.str
            types.path
            types.package
            types.int
          ]
        );
        default = { };
        example = {
          HF_HOME = "/var/lib/hellas/huggingface";
          OTEL_SERVICE_NAME = "hellas";
        };
        description = "Environment variables exported to Hellas processes.";
      };
      otel = otelOptions { inherit lib; };
    };

  otelOptions =
    { lib }:
    let
      inherit (lib) mkOption types;
    in
    {
      endpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "https://jaeger.example.com/v1/traces";
        description = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT — OTLP collector URL. Enables trace export when set.";
      };
      serviceName = mkOption {
        type = types.str;
        default = "hellas-node";
        description = "OTEL_SERVICE_NAME — service name attached to exported spans.";
      };
      sampleRate = mkOption {
        type = types.nullOr (types.numbers.between 0.0 1.0);
        default = null;
        example = 0.5;
        description = "OTEL_TRACES_SAMPLER_ARG — trace sample rate (0.0–1.0). Null uses the CLI default of 1.0.";
      };
      headers = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          CF-Access-Client-Id = "abc123";
          CF-Access-Client-Secret = "secret";
        };
        description = ''
          OTEL_EXPORTER_OTLP_HEADERS — extra headers sent with each OTLP export request.
          Useful for Cloudflare Access or other auth proxies.
        '';
      };
    };

  # Serve-daemon options. Reused by NixOS systemd, HM-on-darwin launchd, and
  # any other future daemon surface. The keys here mirror `hellas-cli serve`'s
  # CLI flags one-for-one — see `mkServeArgs` for the binding.
  serveOptions =
    { lib, pkgs }:
    let
      inherit (lib) mkOption types;
    in
    {
      port = mkOption {
        type = types.nullOr types.port;
        default = pkgs.hellasLib.executorPort;
        description = "Port for the Hellas node to listen on. Null lets the CLI auto-select.";
      };
      executePolicy = mkOption {
        type = types.nullOr (types.either types.str (types.listOf types.str));
        default = null;
        example = [
          "hf/Qwen/*"
          "graph/llm/*"
        ];
        description = ''
          Graph execution policy.
          "skip" (CLI default) refuses all executions,
          "eager" executes any graph,
          and "allow(hf/pattern,...,graph/pattern,...)" executes only matching requests.
          A list of patterns is shorthand for "allow(p1,p2,...)".
        '';
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Maximum number of queued executions waiting behind the active worker.";
      };
      preloadWeights = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Model identifiers to preload on startup.";
      };
      fetchConfig = mkOption {
        type = types.nullOr types.attrs;
        default = null;
        example = {
          routes = [
            {
              service = "codex";
              method = "responses";
              protocol = "openai-responses";
              upstream.type = "codex-oauth";
              capabilities = {
                models = [ "gpt-5.5-codex" ];
                max_output_tokens = 131072;
              };
            }
          ];
          callers = [
            {
              public_key = "<compressed secp256k1 hex>";
              routes = [
                {
                  service = "codex";
                  method = "responses";
                  max_output_tokens = 65536;
                }
              ];
            }
          ];
        };
        description = "Unified Fetch configuration: routes (provider upstreams, protocols, capabilities) and caller access policy. Rendered to JSON and passed as --fetch-config. Null disables Fetch serving.";
      };
      fetchMaxInFlight = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Maximum number of Fetch provider streams running at once.";
      };
      fetchQueueSize = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum number of Fetch executions waiting behind active provider streams.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional Prometheus metrics port.";
      };
      assurance = mkOption {
        type = types.enum [
          "producer-signed"
          "apple-app-attest"
        ];
        default = "producer-signed";
        description = "Assurance requested from and served by the execution provider.";
      };
      graffiti = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Operator graffiti tag (up to 16 bytes, padded/truncated). Self-reported to peers.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to `hellas-cli serve`.";
      };
    };

  gatewayOptions =
    { lib }:
    let
      inherit (lib) mkEnableOption mkOption types;
    in
    {
      enable = mkEnableOption "Hellas HTTP gateway";
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Host interface for the HTTP gateway to bind.";
      };
      port = mkOption {
        type = types.nullOr types.port;
        default = 8080;
        description = "HTTP gateway port. Null lets the CLI auto-select.";
      };
      nodeId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Direct target node id. Null enables discovery unless local mode is selected.";
      };
      nodeAddrs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Direct UDP address hints for the target node.";
      };
      local = mkOption {
        type = types.bool;
        default = false;
        description = "Run the gateway against an in-process catgrad executor.";
      };
      verifyLocal = mkOption {
        type = types.bool;
        default = false;
        description = "Verify remote responses against an in-process catgrad executor.";
      };
      verifyNodeId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Remote node id used as the verification shadow.";
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Maximum number of queued local executions.";
      };
      retries = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum execution retries in discovery mode.";
      };
      defaultMaxTokens = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Fallback max output tokens when a request omits a limit.";
      };
      forceModel = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Model id that replaces the model named by incoming requests.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional Prometheus metrics port.";
      };
      dtype = mkOption {
        type = types.nullOr (
          types.enum [
            "f32"
            "f16"
            "bf16"
            "f8"
          ]
        );
        default = null;
        description = "Dtype used by local gateway execution and verification.";
      };
      responsesBackend = mkOption {
        type = types.enum [
          "hellas"
          "proxy"
          "fetch"
        ];
        default = "hellas";
        description = "Backend used by the OpenAI Responses endpoint.";
      };
      responsesProxyUrl = mkOption {
        type = types.str;
        default = "https://api.openai.com/v1/responses";
        description = "Upstream endpoint used when responsesBackend is proxy.";
      };
      responsesProxyApiKeyEnv = mkOption {
        type = types.str;
        default = "OPENAI_API_KEY";
        description = "Environment variable containing the Responses proxy bearer token.";
      };
      responsesFetchRouteService = mkOption {
        type = types.str;
        default = "codex";
        description = "Fetch route service used when responsesBackend is fetch.";
      };
      responsesFetchRouteMethod = mkOption {
        type = types.str;
        default = "responses";
        description = "Fetch route method used when responsesBackend is fetch.";
      };
      responsesFetchRequestOverrides = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        description = "JSON object merged into OpenAI Responses requests before signing and sending them through Fetch.";
      };
      trustedProducerPublicKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Compressed secp256k1 producer public keys trusted to sign Fetch output when responsesBackend is fetch. Empty trusts only the gateway's own producer key.";
      };
      assurance = mkOption {
        type = types.enum [
          "producer-signed"
          "apple-app-attest"
        ];
        default = "producer-signed";
        description = "Assurance requested from the selected execution provider.";
      };
      identityPath = mkOption {
        type = types.str;
        default = "/var/lib/hellas-gateway/.hellas/identity";
        description = "Versioned provider identity used by the HTTP gateway.";
      };
      environmentFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/secrets/hellas-gateway.env";
        description = "Optional systemd EnvironmentFile path for gateway-only settings.";
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the HTTP gateway port in the firewall.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to `hellas-cli gateway`.";
      };
    };

  # OTEL_EXPORTER_OTLP_* env vars derived from a resolved `otel` cfg.
  # Returns {} when no endpoint is set so callers can `//`-merge unconditionally.
  mkOtelEnv =
    {
      lib,
      otel,
    }:
    lib.optionalAttrs (otel.endpoint != null) (
      {
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = otel.endpoint;
        OTEL_SERVICE_NAME = otel.serviceName;
      }
      // lib.optionalAttrs (otel.sampleRate != null) {
        OTEL_TRACES_SAMPLER_ARG = toString otel.sampleRate;
      }
      // lib.optionalAttrs (otel.headers != { }) {
        OTEL_EXPORTER_OTLP_HEADERS = lib.concatStringsSep "," (
          lib.mapAttrsToList (k: v: "${k}=${v}") otel.headers
        );
      }
    );

  # `hellas-cli serve ...` argv from a resolved serve cfg. The cfg shape is
  # whatever attrset carries `serveOptions` keys — for NixOS that's the top-
  # level `services.hellas`, for HM-darwin it's `programs.hellas.serve`.
  mkServeArgs =
    {
      lib,
      serve,
    }:
    let
      optArg =
        flag: value:
        lib.optionals (value != null) [
          flag
          (toString value)
        ];
      renderPolicy =
        value:
        if value == null then
          null
        else if lib.isList value then
          "allow(${lib.concatStringsSep "," value})"
        else
          value;
    in
    [ "serve" ]
    ++ optArg "--port" serve.port
    ++ optArg "--execute-policy" (renderPolicy serve.executePolicy)
    ++ optArg "--queue-size" serve.queueSize
    ++ optArg "--metrics-port" serve.metricsPort
    ++ [
      "--assurance"
      serve.assurance
    ]
    ++ optArg "--graffiti" serve.graffiti
    ++ lib.concatMap (model: [
      "--preload"
      model
    ]) serve.preloadWeights
    ++ lib.optionals (serve.fetchConfig != null) [
      "--fetch-config"
      (builtins.toFile "hellas-fetch-config.json" (builtins.toJSON serve.fetchConfig))
    ]
    ++ optArg "--fetch-max-in-flight" serve.fetchMaxInFlight
    ++ optArg "--fetch-queue-size" serve.fetchQueueSize
    ++ serve.extraArgs;

  mkGatewayArgs =
    {
      lib,
      gateway,
    }:
    let
      optArg =
        flag: value:
        lib.optionals (value != null) [
          flag
          (toString value)
        ];
    in
    [
      "--identity"
      gateway.identityPath
      "gateway"
      "--assurance"
      gateway.assurance
    ]
    ++ [
      "--host"
      gateway.host
    ]
    ++ optArg "--port" gateway.port
    ++ optArg "--node-id" gateway.nodeId
    ++ lib.concatMap (addr: [
      "--node-addr"
      addr
    ]) gateway.nodeAddrs
    ++ lib.optionals gateway.local [ "--local" ]
    ++ lib.optionals gateway.verifyLocal [ "--verify-local" ]
    ++ optArg "--verify" gateway.verifyNodeId
    ++ optArg "--queue-size" gateway.queueSize
    ++ optArg "--retries" gateway.retries
    ++ optArg "--default-max-tokens" gateway.defaultMaxTokens
    ++ optArg "--force-model" gateway.forceModel
    ++ optArg "--metrics-port" gateway.metricsPort
    ++ optArg "--dtype" gateway.dtype
    ++ [
      "--responses-backend"
      gateway.responsesBackend
      "--responses-proxy-url"
      gateway.responsesProxyUrl
      "--responses-proxy-api-key-env"
      gateway.responsesProxyApiKeyEnv
      "--responses-fetch-route-service"
      gateway.responsesFetchRouteService
      "--responses-fetch-route-method"
      gateway.responsesFetchRouteMethod
    ]
    ++ lib.optionals (gateway.responsesFetchRequestOverrides != { }) [
      "--responses-fetch-request-overrides"
      (builtins.toJSON gateway.responsesFetchRequestOverrides)
    ]
    ++ lib.concatMap (key: [
      "--trusted-producer-public-key"
      key
    ]) gateway.trustedProducerPublicKeys
    ++ gateway.extraArgs;
}
