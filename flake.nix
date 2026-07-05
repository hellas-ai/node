{
  description = "Hellas Node";

  # CA derivations let the HF cache packages (and any other system-independent
  # outputs) substitute across Linux/Darwin from a shared binary cache.
  # extra-substituters / extra-trusted-public-keys are an opt-in for downstream
  # users — nix will prompt to accept on first use (or auto-accept with
  # `--accept-flake-config`).
  nixConfig = {
    extra-experimental-features = [ "ca-derivations" ];
    extra-substituters = [ "https://cache.hellas.ai" ];
    extra-trusted-public-keys = [ "cache.hellas.ai-1:PYolh95U/Ms5fKE+NQTcNZUHyEv4QikaNocg9I9iy0g=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    catgrad = {
      url = "github:hellas-ai/catgrad";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      catgrad,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      hydraSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      forHydraSystems = nixpkgs.lib.genAttrs hydraSystems;
      perSystem = forAllSystems (
        system:
        import ./nix {
          inherit
            self
            system
            nixpkgs
            rust-overlay
            catgrad
            ;
        }
      );
    in
    {
      packages = forAllSystems (system: perSystem.${system}.packages);
      apps = forAllSystems (system: perSystem.${system}.apps);
      devShells = forAllSystems (system: perSystem.${system}.devShells);
      checks = forAllSystems (system: perSystem.${system}.checks);
      nixosTests = forAllSystems (system: perSystem.${system}.nixosTests);
      ci = forAllSystems (system: perSystem.${system}.ci);
      hydraJobs = forHydraSystems (system: perSystem.${system}.hydraJobs);
      formatter = forAllSystems (system: perSystem.${system}.formatter);

      overlays.default = final: _prev: {
        hellas = self.packages.${final.system};
        hellasLib = import ./nix/lib { pkgs = final; };
      };

      nixosModules.hellas = import ./nix/modules/nixos.nix { inherit self; };
      nixosModules.default = self.nixosModules.hellas;

      homeManagerModules.hellas = import ./nix/modules/home-manager.nix { inherit self; };
      homeManagerModules.default = self.homeManagerModules.hellas;
    };
}
