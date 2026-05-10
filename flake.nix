{
  description = "Hellas Kernel";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
  }: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
    ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {inherit system overlays;};
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          rustToolchain
          rust-analyzer
          llvmPackages.lld
          nodejs_24
          pkg-config
          temurin-bin   # JVM for Apalache (auto-downloaded by `quint verify`)
          stdenv.cc.cc.lib   # libstdc++ for Apalache's bundled native Z3

          cargo-audit
          cargo-deny
          cargo-fuzz
          cargo-llvm-cov
          cargo-mutants
          cargo-nextest
          cargo-outdated
          cargo-sort
          cargo-watch

          git
          jq
          just
          taplo
        ];

        RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        # Quint downloads the Apalache JAR + bundled native Z3 to ~/.quint;
        # Z3's libz3java.so dlopens libstdc++ at runtime, so expose it.
        LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
  };
}
