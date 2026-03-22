{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) concatStringsSep mkEnableOption mkIf mkOption types;
  cfg = config.services.hellas;
  cliArgs = concatStringsSep " " (
    ["serve"]
    ++ lib.optionals (cfg.port != null) ["--port" (toString cfg.port)]
    ++ lib.optionals (cfg.downloadPolicy != null) ["--download-policy" cfg.downloadPolicy]
    ++ lib.optionals (cfg.executePolicy != null) ["--execute-policy" cfg.executePolicy]
    ++ cfg.extraArgs
  );
in {
  options.services.hellas = {
    enable = mkEnableOption "Hellas node server";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
      description = "Package providing the hellas CLI (with serve feature).";
    };
    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open firewall port for the hellas node.";
    };
    port = mkOption {
      type = types.nullOr types.port;
      default = null;
      description = "Port for the hellas node to listen on. Null (default) auto-selects.";
    };
    downloadPolicy = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Model download policy.
        "skip" (CLI default) never downloads (cache-only),
        "eager" downloads any requested model,
        "allow(pattern,...)" downloads only matching HF model patterns.
      '';
    };
    executePolicy = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Graph execution policy.
        "skip" (CLI default) refuses all executions,
        "eager" executes any graph,
        "allow(hf/pattern,...,graph/pattern,...)" executes only matching.
      '';
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Extra arguments to pass to `hellas-cli serve`.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.hellas = {
      description = "Hellas node server";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      environment = {
        HOME = "/var/lib/hellas";
      };
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/hellas-cli ${cliArgs}";
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
