{self}: let
  mkPackageDefault = pkgs: packageName: self.packages.${pkgs.stdenv.hostPlatform.system}.${packageName};
in {
  mkCommonOptions = {
    lib,
    pkgs,
    packageName,
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
      default = mkPackageDefault pkgs packageName;
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
