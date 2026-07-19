{
  self,
  hellas ? import ./hellas.nix { inherit self; },
}:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkMerge
    optionals
    ;
  cfg = config.programs.hellas;
  inherit (pkgs.stdenv.hostPlatform) isDarwin;

  baseEnv =
    hellas.mkOtelEnv {
      inherit lib;
      inherit (cfg) otel;
    }
    // cfg.environment;
in
{
  options.programs.hellas =
    hellas.commonOptions {
      inherit lib;
      package = hellas.pickCliPackage pkgs;
      packageDescription = ''
        The hellas CLI package. Defaults to the best backend variant for
        the host: cli-candle-metal on Darwin, cli-candle-cuda when
        `nixpkgs.config.cudaSupport` is enabled on Linux, otherwise
        cli-candle. These builds include OTEL. Override to `pkgs.hellas.cli`
        for the minimal remote-only build without local execution or OTEL.
      '';
    }
    // {
      # User-space serve daemon. Currently darwin-only (uses HM's launchd
      # integration). Linux users should use the NixOS module instead.
      serve = {
        enable = mkEnableOption "Hellas serve daemon as a launchd user agent (darwin only)";
      }
      // hellas.serveOptions { inherit lib pkgs; };
    };

  config = mkMerge [
    (mkIf cfg.enable {
      home.packages = [ cfg.package ];
      home.sessionVariables = hellas.renderEnvironment baseEnv;
    })

    # Surface a clear assertion on Linux rather than a "no such option" error
    # when the user enables `programs.hellas.serve` on the wrong platform.
    (mkIf cfg.serve.enable {
      assertions = optionals (!isDarwin) [
        {
          assertion = false;
          message = ''
            programs.hellas.serve is only supported on darwin (HM launchd).
            On Linux, use the NixOS module `services.hellas` instead.
          '';
        }
      ];
    })

    (mkIf (cfg.serve.enable && isDarwin) {
      launchd.agents.hellas = {
        enable = true;
        config = {
          ProgramArguments = [
            "${cfg.package}/bin/hellas-cli"
          ]
          ++ hellas.mkServeArgs {
            inherit lib;
            inherit (cfg) serve;
          };
          RunAtLoad = true;
          KeepAlive = true;
          EnvironmentVariables = hellas.renderEnvironment (baseEnv // { HOME = config.home.homeDirectory; });
          StandardOutPath = "${config.home.homeDirectory}/Library/Logs/hellas/stdout.log";
          StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/hellas/stderr.log";
        };
      };
    })
  ];
}
