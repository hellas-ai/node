{
  description = "Hellas Node";

  # CA derivations let the HF cache packages (and any other system-independent
  # outputs) substitute across Linux/Darwin from a shared binary cache.
  nixConfig.extra-experimental-features = ["ca-derivations"];

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    catgrad = {
      url = "github:hellas-ai/catgrad";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    catgrad,
  }: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
    ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
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
  in {
    packages = forAllSystems (system: perSystem.${system}.packages);
    apps = forAllSystems (system: perSystem.${system}.apps);
    devShells = forAllSystems (system: perSystem.${system}.devShells);
    checks = forAllSystems (system: perSystem.${system}.checks);
    nixosTests = forAllSystems (system: perSystem.${system}.nixosTests);

    overlays.default = final: _prev: {
      hellas = self.packages.${final.system};
    };

    nixosModules.hellas = import ./nix/modules/nixos.nix {inherit self;};
    nixosModules.default = self.nixosModules.hellas;

    homeManagerModules.hellas = import ./nix/modules/home-manager.nix {inherit self;};
    homeManagerModules.default = self.homeManagerModules.hellas;
  };
}
