{
  self,
  common ? import ./default.nix {inherit self;},
}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.hellas;

  cliArgs =
    [
      "serve"
    ]
    ++ lib.optionals (cfg.port != null) ["--port" (toString cfg.port)]
    ++ lib.optionals (cfg.downloadPolicy != null) ["--download-policy" cfg.downloadPolicy]
    ++ lib.optionals (cfg.executePolicy != null) ["--execute-policy" cfg.executePolicy]
    ++ lib.optionals (cfg.queueSize != null) ["--queue-size" (toString cfg.queueSize)]
    ++ lib.optionals (cfg.metricsPort != null) ["--metrics-port" (toString cfg.metricsPort)]
    ++ lib.optionals (cfg.graffiti != null) ["--graffiti" cfg.graffiti]
    ++ lib.concatMap (model: ["--preload" model]) cfg.preloadWeights
    ++ cfg.extraArgs;

  otelEnv =
    lib.optionalAttrs (cfg.otel.endpoint != null) {
      OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = cfg.otel.endpoint;
      OTEL_SERVICE_NAME = cfg.otel.serviceName;
    }
    // lib.optionalAttrs (cfg.otel.endpoint != null && cfg.otel.sampleRate != null) {
      OTEL_TRACES_SAMPLER_ARG = toString cfg.otel.sampleRate;
    }
    // lib.optionalAttrs (cfg.otel.endpoint != null && cfg.otel.headers != {}) {
      OTEL_EXPORTER_OTLP_HEADERS =
        lib.concatStringsSep "," (lib.mapAttrsToList (k: v: "${k}=${v}") cfg.otel.headers);
    };
in {
  options.services.hellas =
    common.mkCommonOptions {
      inherit lib pkgs;
      packageName = "server";
      packageDescription = "Package providing the hellas CLI with server support.";
    }
    // {
      enable = mkEnableOption "Hellas node server";
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Hellas UDP listen port in the firewall.";
      };
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

      otel = {
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
    };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.hellas is only supported on Linux.";
      }
    ];

    systemd.services.hellas = {
      description = "Hellas node server";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      environment = common.renderEnvironment (otelEnv // cfg.environment // {HOME = "/var/lib/hellas";});
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (["${cfg.package}/bin/hellas-cli"] ++ cliArgs);
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "hellas";
        WorkingDirectory = "/var/lib/hellas";
      };
    };

    networking.firewall = mkIf (cfg.openFirewall && cfg.port != null) {
      allowedUDPPorts = [cfg.port];
    };
  };
}
