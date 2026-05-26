{
  pkgs,
  lib,
  rustToolchain,
  workspaceNativeBuildInputs,
}:
let
  mk =
    name: cmd: inputs:
    pkgs.writeShellApplication {
      inherit name;
      text = ''
        export PATH="${lib.makeBinPath inputs}"
        ${cmd}
      '';
    };

  cargoEnv =
    toolchain:
    [
      toolchain
      pkgs.stdenv.cc
    ]
    ++ workspaceNativeBuildInputs;

  # CI-gating checks. These surface as `apps.<sys>.check-<name>` for local and
  # external matrix runners.
  checks = {
    fmt = mk "check-fmt" "cargo fmt --all -- --check" [ rustToolchain ];
    clippy = mk "check-clippy" "cargo clippy --workspace --all-targets -- -D warnings" (
      cargoEnv rustToolchain
    );
    sort = mk "check-sort" "cargo-sort --workspace --check" [ pkgs.cargo-sort ];
    taplo = mk "check-taplo" "taplo fmt --check '*.toml' 'crates/**/Cargo.toml'" [ pkgs.taplo ];
    buf = mk "check-buf" "buf lint" [ pkgs.buf ];
    deadnix = mk "check-deadnix" ''
      shopt -s globstar
      deadnix --fail flake.nix nix/**/*.nix
    '' [ pkgs.deadnix ];
    statix = mk "check-statix" "statix check ." [ pkgs.statix ];
    nixfmt = mk "check-nixfmt" ''
      shopt -s globstar
      nixfmt --check flake.nix nix/**/*.nix
    '' [ pkgs.nixfmt-rfc-style ];
    flake-check = mk "check-flake-check" "nix flake check --no-build" [ pkgs.nix ];
    wasm-rpc = mk "check-wasm-rpc" "cargo check -p hellas-rpc --target wasm32-unknown-unknown" (
      cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; })
    );
  };

  # Auto-fix variants. Not all checks have one (e.g. test, wasm-rpc).
  fixes = {
    fmt = mk "fix-fmt" "cargo fmt --all" [ rustToolchain ];
    clippy =
      mk "fix-clippy" "cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged"
        (cargoEnv rustToolchain);
    sort = mk "fix-sort" "cargo-sort --workspace" [ pkgs.cargo-sort ];
  };

  # Heuristic — noisy enough to keep out of CI. Surfaced only via
  # `nix run .#check` for occasional dev use.
  outdatedCheck =
    mk "check-outdated"
      ''
        report="$(cargo outdated --workspace --root-deps-only --format json)"
        breaking_updates="$(
          echo "$report" | jq -r '
            . as $pkg
            | .dependencies[]?
            | select(
                .kind != "Development"
                and .latest != "Removed"
                and .latest != "---"
                and .compat == "---"
              )
            | "\($pkg.crate_name)\t\(.name)\t\(.project)\t\(.latest)"
          '
        )"
        if [ -n "$breaking_updates" ]; then
          echo "Semver-breaking root dependency updates available:"
          printf "crate\tdependency\tcurrent\tlatest\n"
          echo "$breaking_updates"
          exit 1
        fi
        echo "No semver-breaking root dependency updates detected."
      ''
      (
        with pkgs;
        [
          rustToolchain
          cargo-outdated
          jq
        ]
      );

  # `nix run .#check` runs every gating check plus outdated.
  # `nix run .#fix`   runs the auto-fix variants.
  mkAggregate =
    name: pkgList:
    pkgs.writeShellApplication {
      inherit name;
      text = lib.concatMapStringsSep "\n" lib.getExe pkgList;
    };

  # Extended builds. Each value is an attribute path under `packages.<system>`
  # consumed by matrix runners as
  # `nix build .#packages.<system>.<attr>`.
  ciBuilds = {
    cli = "cli";
    cli-candle = "cli-candle";
    static-x86_64 = "cross-x86_64-linux-musl-cli";
    static-aarch64 = "cross-aarch64-linux-musl-cli";
    static-windows = "cross-x86_64-windows-cli";
    docker-cuda = "docker-cuda";
    hellas-rpc-wasm = "hellas-rpc-wasm";
  };
in
{
  inherit checks fixes;
  builds = ciBuilds;
  checkAll = mkAggregate "check-all" ((lib.attrValues checks) ++ [ outdatedCheck ]);
  fixAll = mkAggregate "fix-all" (lib.attrValues fixes);
}
