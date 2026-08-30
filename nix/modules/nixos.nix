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
      package = hellas.nixosCliPackage pkgs;
      packageDescription =
        if hellas.catenaPlatform pkgs then
          ''
            The hellas CLI used to run the serve daemon. On x86_64-linux it
            defaults to `pkgs.hellas.cli-catena`, which can materialize and
            execute Catena packages. Override with `pkgs.hellas.cli` for a
            network-only node.
          ''
        else
          ''
            The hellas network CLI used to run the serve daemon. Local Catena
            execution is currently available only on x86_64-linux because the
            runner uses a HIP-only backend.
          '';
    }
    // hellas.serveOptions { inherit lib pkgs; }
    // {
      gateway = hellas.gatewayOptions { inherit lib; } // {
        package = mkOption {
          type = types.package;
          default = cfg.package;
          defaultText = lib.literalMD ''
            `services.hellas.package`: the platform's default node CLI.
          '';
          description = ''
            The hellas CLI used to run the HTTP gateway. The default supports
            local Catena execution only on x86_64-linux; other platforms use
            the network-only CLI.
          '';
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
        assertion =
          hellas.catenaPlatform pkgs
          || (cfg.executionPackages == { } && !gateway.local && !gateway.verifyLocal);
        message = "Local Catena execution is supported only on x86_64-linux; use the network CLI without executionPackages, gateway.local, or gateway.verifyLocal on this platform.";
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
        assertion = !(gateway.local || gateway.verifyLocal) || gateway.executionPackagePath != null;
        message = "services.hellas.gateway.executionPackagePath is required for local execution or local verification.";
      }
      {
        assertion = gateway.executionPackagePath == null || gateway.local || gateway.verifyLocal;
        message = "services.hellas.gateway.executionPackagePath is only valid for local execution or local verification.";
      }
      {
        assertion = !gateway.enable || gateway.local || gateway.verifyLocal || gateway.packageId != null;
        message = "services.hellas.gateway.packageId is required for remote execution.";
      }
      {
        assertion = !(gateway.local || gateway.verifyLocal) || gateway.packageId == null;
        message = "services.hellas.gateway.packageId must be omitted for local execution or local verification; it is derived from the verified local package.";
      }
      {
        assertion = gateway.verifyNodeId == null || gateway.nodeId != null;
        message = "services.hellas.gateway.verifyNodeId requires services.hellas.gateway.nodeId.";
      }
      {
        assertion =
          gateway.provider != null
          || (gateway.nodeId == null && gateway.verifyNodeId == null && gateway.responsesBackend != "fetch");
        message = "services.hellas.gateway.provider is required by nodeId, verifyNodeId, and responsesBackend = \"fetch\", each of which dials a provider.";
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
