{
  self,
  common ? import ./default.nix {inherit self;},
}:
{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.programs.hellas;

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
  options.programs.hellas =
    common.mkCommonOptions {
      inherit lib pkgs;
      packageName = "cli";
      packageDescription = "Package providing the hellas CLI.";
    }
    // {
      enable = mkEnableOption "Hellas CLI";

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
    home.packages = [cfg.package];
    home.sessionVariables = common.renderEnvironment (otelEnv // cfg.environment);
  };
}
