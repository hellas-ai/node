{self}: rec {
  # Pick the best available hellas CLI variant for the target system:
  #   Darwin         → cli-metal
  #   Linux + cuda   → cli-cuda  (requires `nixpkgs.config.cudaSupport = true`)
  #   otherwise      → cli-cpu
  # Each step checks the package set for membership so a missing variant
  # falls through instead of erroring.
  pickCliPackage = pkgs: let
    pkgSet = self.packages.${pkgs.stdenv.hostPlatform.system};
    isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
    cudaEnabled = pkgs.config.cudaSupport or false;
  in
    if isDarwin && pkgSet ? cli-metal
    then pkgSet.cli-metal
    else if cudaEnabled && pkgSet ? cli-cuda
    then pkgSet.cli-cuda
    else pkgSet.cli-cpu;

  mkCommonOptions = {
    lib,
    package,
    packageDescription,
  }: let
    inherit (lib) mkOption types;
    envValueType = types.oneOf [
      types.str
      types.path
      types.package
      types.int
    ];
  in {
    package = mkOption {
      type = types.package;
      default = package;
      description = packageDescription;
    };
    environment = mkOption {
      type = types.attrsOf envValueType;
      default = {};
      example = {
        HF_HOME = "/var/lib/hellas/huggingface";
        OTEL_SERVICE_NAME = "hellas";
      };
      description = "Environment variables exported to Hellas processes.";
    };
  };

  renderEnvironment = environment:
    builtins.mapAttrs (_name: value: toString value) environment;
}
