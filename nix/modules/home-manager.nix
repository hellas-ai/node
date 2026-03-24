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
  inherit (lib) mkEnableOption mkIf;
  cfg = config.programs.hellas;
in {
  options.programs.hellas =
    common.mkCommonOptions {
      inherit lib pkgs;
      packageName = "cli";
      packageDescription = "Package providing the hellas CLI.";
    }
    // {
      enable = mkEnableOption "Hellas CLI";
    };

  config = mkIf cfg.enable {
    home.packages = [cfg.package];
    home.sessionVariables = common.renderEnvironment cfg.environment;
  };
}
