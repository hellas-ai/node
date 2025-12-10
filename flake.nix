{
  description = "Hellas Node";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      # Use the toolchain specified in our rust-toolchain.toml
      rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatform = pkgs.makeRustPlatform {
        rustc = rust-toolchain;
        cargo = rust-toolchain;
      };

      # Main executable
      hellas = rustPlatform.buildRustPackage {
        pname = "hellas";
        version = "0.1.0";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
        };
        auditable = false;
        nativeBuildInputs = with pkgs; [protobuf];
        checkInputs = with pkgs; [cargo-audit cargo-deny cargo-outdated];
      };
    in {
      packages = {
        default = hellas;
        inherit hellas;
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [self.packages.${system}.default];
        buildInputs = with pkgs; [
          pre-commit
          protobuf-language-server
          cargo-watch
          gh
        ];
      };

      # For compatibility with older nix-shell
      devShell = self.devShells.${system}.default;
    });
}
