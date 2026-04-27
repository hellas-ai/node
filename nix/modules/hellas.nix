{self}: rec {
  # Pick the best available hellas CLI variant for the target system:
  #   Darwin         → cli-candle-metal
  #   Linux + cuda   → cli-candle-cuda  (requires `nixpkgs.config.cudaSupport = true`)
  #   otherwise      → cli-candle
  # Each step checks the package set for membership so a missing variant
  # falls through instead of erroring.
  pickCliPackage = pkgs: let
    pkgSet = self.packages.${pkgs.stdenv.hostPlatform.system};
    isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
    cudaEnabled = pkgs.config.cudaSupport or false;
  in
    if isDarwin && pkgSet ? cli-candle-metal
    then pkgSet.cli-candle-metal
    else if cudaEnabled && pkgSet ? cli-candle-cuda
    then pkgSet.cli-candle-cuda
    else pkgSet.cli-candle;

  renderEnvironment = environment:
    builtins.mapAttrs (_name: value: toString value) environment;

  commonOptions = {
    lib,
    package,
    packageDescription,
  }: let
    inherit (lib) mkEnableOption mkOption types;
  in {
    enable = mkEnableOption "Hellas";
    package = mkOption {
      type = types.package;
      default = package;
      description = packageDescription;
    };
    environment = mkOption {
      type = types.attrsOf (types.oneOf [
        types.str
        types.path
        types.package
        types.int
      ]);
      default = {};
      example = {
        HF_HOME = "/var/lib/hellas/huggingface";
        OTEL_SERVICE_NAME = "hellas";
      };
      description = "Environment variables exported to Hellas processes.";
    };
    otel = otelOptions {inherit lib;};
  };

  otelOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
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
      default = {};
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
  serveOptions = {lib}: let
    inherit (lib) mkOption types;
  in {
    port = mkOption {
      type = types.nullOr types.port;
      default = null;
      description = "Port for the Hellas node to listen on. Null lets the CLI auto-select.";
    };
    downloadPolicy = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Model download policy.
        "skip" (CLI default) never downloads,
        "eager" downloads any requested model,
        and "allow(pattern,...)" downloads only matching Hugging Face models.
      '';
    };
    executePolicy = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Graph execution policy.
        "skip" (CLI default) refuses all executions,
        "eager" executes any graph,
        and "allow(hf/pattern,...,graph/pattern,...)" executes only matching requests.
      '';
    };
    queueSize = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "Maximum number of queued executions waiting behind the active worker.";
    };
    preloadWeights = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Model identifiers to preload on startup.";
    };
    metricsPort = mkOption {
      type = types.nullOr types.port;
      default = null;
      description = "Optional Prometheus metrics port.";
    };
    graffiti = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Operator graffiti tag (up to 16 bytes, padded/truncated). Self-reported to peers.";
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Extra arguments to pass to `hellas-cli serve`.";
    };
  };

  # OTEL_EXPORTER_OTLP_* env vars derived from a resolved `otel` cfg.
  # Returns {} when no endpoint is set so callers can `//`-merge unconditionally.
  mkOtelEnv = {
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
      // lib.optionalAttrs (otel.headers != {}) {
        OTEL_EXPORTER_OTLP_HEADERS =
          lib.concatStringsSep "," (lib.mapAttrsToList (k: v: "${k}=${v}") otel.headers);
      }
    );

  # `hellas-cli serve ...` argv from a resolved serve cfg. The cfg shape is
  # whatever attrset carries `serveOptions` keys — for NixOS that's the top-
  # level `services.hellas`, for HM-darwin it's `programs.hellas.serve`.
  mkServeArgs = {
    lib,
    serve,
  }: let
    optArg = flag: value: lib.optionals (value != null) [flag (toString value)];
  in
    ["serve"]
    ++ optArg "--port" serve.port
    ++ optArg "--download-policy" serve.downloadPolicy
    ++ optArg "--execute-policy" serve.executePolicy
    ++ optArg "--queue-size" serve.queueSize
    ++ optArg "--metrics-port" serve.metricsPort
    ++ optArg "--graffiti" serve.graffiti
    ++ lib.concatMap (model: ["--preload" model]) serve.preloadWeights
    ++ serve.extraArgs;
}
