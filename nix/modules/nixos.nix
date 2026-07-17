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
  inherit (lib) mkIf mkOption types;
  cfg = config.services.hellas;
  inherit (cfg) gateway;
in
{
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
    // hellas.serveOptions { inherit lib pkgs; }
    // {
      gateway = hellas.gatewayOptions { inherit lib; } // {
        package = mkOption {
          type = types.package;
          default =
            if gateway.local || gateway.verifyLocal then cfg.package else hellas.pickGatewayPackage pkgs;
          defaultText = lib.literalMD ''
            The slim gateway CLI (`packages.cli`), or `services.hellas.package`
            when `gateway.local` / `gateway.verifyLocal` request an in-process
            executor.
          '';
          description = "The hellas CLI used to run the HTTP gateway.";
        };
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Hellas UDP listen port in the firewall.";
      };
    };

  config = mkIf (cfg.enable || gateway.enable) {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.hellas is only supported on Linux.";
      }
      {
        assertion = gateway.nodeAddrs == [ ] || gateway.nodeId != null;
        message = "services.hellas.gateway.nodeAddrs requires services.hellas.gateway.nodeId.";
      }
      {
        assertion =
          !gateway.local
          || (gateway.nodeId == null && gateway.nodeAddrs == [ ] && gateway.verifyNodeId == null);
        message = "services.hellas.gateway.local cannot be combined with direct or verification node ids.";
      }
      {
        assertion = !(gateway.local && gateway.verifyLocal);
        message = "services.hellas.gateway.local and services.hellas.gateway.verifyLocal are mutually exclusive.";
      }
      {
        assertion = !(gateway.verifyLocal && gateway.verifyNodeId != null);
        message = "services.hellas.gateway.verifyLocal and services.hellas.gateway.verifyNodeId are mutually exclusive.";
      }
      {
        assertion = gateway.verifyNodeId == null || gateway.nodeId != null;
        message = "services.hellas.gateway.verifyNodeId requires services.hellas.gateway.nodeId.";
      }
    ];

    systemd.services.hellas = mkIf cfg.enable {
      description = "Hellas node server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = pkgs.hellasLib.defaultStateDir;
        }
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${cfg.package}/bin/hellas-cli" ]
          ++ hellas.mkServeArgs {
            inherit lib;
            serve = cfg;
          }
        );
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "hellas";
        WorkingDirectory = pkgs.hellasLib.defaultStateDir;
      };
    };

    systemd.services.hellas-gateway = mkIf gateway.enable {
      description = "Hellas HTTP gateway";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = "/var/lib/hellas-gateway";
        }
        // lib.optionalAttrs (cfg.otel.endpoint != null) {
          # Distinguish gateway spans from the node's in shared trace storage.
          OTEL_SERVICE_NAME = "${cfg.otel.serviceName}-gateway";
        }
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${gateway.package}/bin/hellas-cli" ]
          ++ hellas.mkGatewayArgs {
            inherit lib gateway;
          }
        );
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "hellas-gateway";
        WorkingDirectory = "/var/lib/hellas-gateway";
      }
      // lib.optionalAttrs (gateway.environmentFile != null) {
        EnvironmentFile = gateway.environmentFile;
      };
    };

    networking.firewall = {
      allowedUDPPorts = lib.optionals (cfg.enable && cfg.openFirewall && cfg.port != null) [ cfg.port ];
      allowedTCPPorts = lib.optionals (gateway.enable && gateway.openFirewall && gateway.port != null) [
        gateway.port
      ];
    };
  };
}
