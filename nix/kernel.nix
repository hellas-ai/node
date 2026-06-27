{
  pkgs,
  lib,
  rustToolchain,
  cargoToolPackages,
  commonToolPackages,
}:
let
  modelRuntimePackages = with pkgs; [
    nodejs_24
    temurin-bin
    stdenv.cc.cc.lib
  ];

  devShellPackages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.llvmPackages.lld
    pkgs.pkg-config
    pkgs.git
  ]
  ++ modelRuntimePackages
  ++ cargoToolPackages
  ++ commonToolPackages;

  mkModelApp =
    {
      name,
      npmScript,
      needsJvm ? false,
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.git
        pkgs.nodejs_24
      ]
      ++ lib.optionals needsJvm [ pkgs.temurin-bin ];
      text = ''
        repo_root="$(git rev-parse --show-toplevel)"
        cd "$repo_root/crates/kernel"
        npm ci
        ${lib.optionalString needsJvm ''
          export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
        ''}
        npm run ${npmScript}
      '';
    };

  modelTest = mkModelApp {
    name = "hellas-kernel-model-test";
    npmScript = "quint:test";
  };

  modelVerify = mkModelApp {
    name = "hellas-kernel-model-verify";
    npmScript = "quint:verify";
    needsJvm = true;
  };
in
{
  devShell = pkgs.mkShell {
    packages = devShellPackages;
    RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
    # Quint's Apalache backend dlopens libstdc++ through its bundled Z3.
    LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
  };

  apps = {
    "check-kernel-models" = {
      type = "app";
      program = lib.getExe modelTest;
      meta.description = "Run hellas-kernel Quint model tests";
    };
    "check-kernel-model-verify" = {
      type = "app";
      program = lib.getExe modelVerify;
      meta.description = "Run hellas-kernel Quint model verification";
    };
  };
}
