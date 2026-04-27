{
  self,
  hellas ? import ./hellas.nix {inherit self;},
}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkIf mkOption types;
  cfg = config.services.hellas;
in {
  options.services.hellas =
    hellas.commonOptions {
      inherit lib;
      package = hellas.pickCliPackage pkgs;
      packageDescription = ''
        The hellas CLI used to run the serve daemon. Defaults to the best
        backend variant for the host: cli-candle-metal on Darwin,
        cli-candle-cuda when `nixpkgs.config.cudaSupport` is enabled on
        Linux, otherwise cli-candle. Override to a specific SM build (e.g.
        `pkgs.hellas.cli-candle-cuda-cuda12-sm80`) to pin a particular GPU
        generation.
      '';
    }
    // hellas.serveOptions {inherit lib;}
    // {
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Hellas UDP listen port in the firewall.";
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
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {HOME = "/var/lib/hellas";}
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          ["${cfg.package}/bin/hellas-cli"]
          ++ hellas.mkServeArgs {
            inherit lib;
            serve = cfg;
          }
        );
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
