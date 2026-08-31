{
  description = "Hellas Node";

  # The binary cache is opt-in for downstream users: nix prompts on first use
  # (or accepts it with `--accept-flake-config`).
  nixConfig = {
    extra-substituters = [ "https://cache.hellas.ai" ];
    extra-trusted-public-keys = [ "cache.hellas.ai-1:PYolh95U/Ms5fKE+NQTcNZUHyEv4QikaNocg9I9iy0g=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    # Temporary committed-only sibling while the safe runtime API is developed
    # in tandem. Replace this local Git URL when that Catena branch is published.
    catena-lang = {
      # A Git input sees only committed files. In particular, it cannot sweep
      # Catena's target/ tree into the Nix store as a raw path input could.
      url = "git+file:../catena-lang?ref=grw/hellas-safe-runtime";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      catena-lang,
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
            catena-lang
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

      nixosModules = {
        hellas = import ./nix/modules/nixos.nix { inherit self; };
        validators = import ./nix/modules/validators.nix { inherit self; };
        default = self.nixosModules.hellas;
      };

      homeManagerModules.hellas = import ./nix/modules/home-manager.nix { inherit self; };
      homeManagerModules.default = self.homeManagerModules.hellas;
    };
}
