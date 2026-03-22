{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}: let
  repoRoot = ../.;
  overlays = [(import rust-overlay)];
  pkgs = import nixpkgs {
    inherit system overlays;
    config.allowUnfree = true;
  };
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;

  rust-toolchain = pkgs.buildPackages.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = pkgs.makeRustPlatform {
    rustc = rust-toolchain;
    cargo = rust-toolchain;
  };

  buildSrc = pkgs.lib.cleanSourceWith {
    src = repoRoot;
    filter = path: type:
      let
        name = builtins.baseNameOf (toString path);
      in
        pkgs.lib.cleanSourceFilter path type
        && !(builtins.elem name [
          ".claude"
          ".direnv"
          ".envrc"
          "result"
          "target"
        ])
        && !pkgs.lib.hasPrefix "result-" name;
  };

  workspaceBuildInputs = with pkgs; [openssl];
  workspaceNativeBuildInputs = with pkgs; [pkg-config protobuf llvmPackages.lld];
  devShellPackages = with pkgs; [
    rust-toolchain
    openssl
    pkg-config
    protobuf
    llvmPackages.lld
    pre-commit
    protobuf-language-server
    cargo-watch
    gh
    depHygiene
    skopeo
  ];

  commonArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "catgrad-0.2.1" = "sha256-xkAEnK1IbTygDLi/jgiV9ksE6fo0mhWVLaG6i4lrK2A=";
      };
    };
    auditable = false;
    buildInputs = workspaceBuildInputs;
    nativeBuildInputs = workspaceNativeBuildInputs;
    checkInputs = with pkgs; [cargo-outdated];
    separateDebugInfo = true;
    meta.mainProgram = "hellas-cli";
  };

  depHygiene = pkgs.writeShellApplication {
    name = "dep-hygiene";
    runtimeInputs = with pkgs; [
      rust-toolchain
      cargo-audit
      cargo-outdated
      jq
      gitMinimal
      gnugrep
      gawk
      coreutils
    ];
    text = ''
      set -euo pipefail

      usage() {
        cat <<'USAGE'
      Usage: dep-hygiene <command>

      Commands:
        check        Run CI-oriented checks (major outdated, audit, update dry-run)
        outdated     Print root dependency outdated report
        major        Fail if a root dependency has a newer major available
        audit        Run cargo audit
        update-check Fail if cargo update would change Cargo.lock
        update       Run cargo update --workspace (mutates Cargo.lock)
      USAGE
      }

      if [ "''${1:-}" = "" ] || [ "''${1:-}" = "-h" ] || [ "''${1:-}" = "--help" ]; then
        usage
        exit 0
      fi

      cmd="$1"
      shift || true

      workspace_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
      cd "$workspace_root"

      # Some restricted environments (e.g. sandboxed CI) can't write ~/.cargo.
      default_cargo_home="''${CARGO_HOME:-$HOME/.cargo}"
      if [ ! -d "$default_cargo_home" ] || [ ! -w "$default_cargo_home" ]; then
        export CARGO_HOME="$workspace_root/.cargo-home"
        mkdir -p "$CARGO_HOME"
      fi

      prepare_external_path_symlinks() {
        local manifest rel src link
        for manifest in Cargo.toml crates/*/Cargo.toml; do
          [ -f "$manifest" ] || continue
          while IFS= read -r rel; do
            case "$rel" in
              ../*)
                src="$(realpath -m "$workspace_root/$rel")"
                [ -e "$src" ] || continue
                link="$(realpath -m "/tmp/cargo-outdated-workspace/$rel")"
                case "$link" in
                  /tmp/*)
                    mkdir -p "$(dirname "$link")"
                    ln -sfn "$src" "$link"
                    ;;
                esac
                ;;
            esac
          done < <(
            grep -oE 'path[[:space:]]*=[[:space:]]*"[^"]+"' "$manifest" \
              | sed -E 's/.*"([^"]+)".*/\1/'
          )
        done
      }

      outdated_json() {
        prepare_external_path_symlinks
        cargo outdated --workspace --root-deps-only --ignore-external-rel --format json
      }

      check_major() {
        local major_rows
        major_rows="$(
          outdated_json | jq -r '
            def deps:
              if type == "array" then .
              elif has("dependencies") then .dependencies
              elif has("packages") then .packages
              else [] end;
            def major(v):
              (try (v | tostring | capture("^(?<m>[0-9]+)").m | tonumber) catch -1);
            deps
            | map(
                . as $d
                | ($d.name // $d.crate // $d.package // "unknown") as $name
                | ($d.project // $d.current // "") as $current
                | ($d.latest // "") as $latest
                | select(major($latest) > major($current))
                | "\($name)\t\($current)\t\($latest)"
              )
            | .[]
          '
        )"

        if [ -n "$major_rows" ]; then
          echo "major dependency updates available:"
          echo "$major_rows" | awk 'BEGIN { printf "%-36s %-14s %-14s\n", "crate", "current", "latest" }
                                      { printf "%-36s %-14s %-14s\n", $1, $2, $3 }'
          return 1
        fi

        echo "no major root dependency updates found"
      }

      update_check() {
        local out
        out="$(cargo update --workspace --dry-run "$@" 2>&1 || true)"
        printf "%s\n" "$out"
        if printf "%s\n" "$out" | grep -Eq 'Locking [1-9][0-9]* packages?'; then
          echo "cargo update would modify Cargo.lock"
          return 1
        fi
        echo "Cargo.lock is up to date with cargo update --workspace"
      }

      case "$cmd" in
        check)
          status=0
          check_major || status=1
          cargo audit || status=1
          update_check "$@" || status=1
          exit "$status"
          ;;
        outdated)
          prepare_external_path_symlinks
          cargo outdated --workspace --root-deps-only --ignore-external-rel
          ;;
        major)
          check_major
          ;;
        audit)
          cargo audit
          ;;
        update-check)
          update_check "$@"
          ;;
        update)
          cargo update --workspace "$@"
          ;;
        *)
          echo "unknown command: $cmd"
          usage
          exit 2
          ;;
      esac
    '';
  };

  cli = rustPlatform.buildRustPackage (
    commonArgs
    // pkgs.lib.optionalAttrs isDarwin {
      buildFeatures = ["metal"];
    }
  );
  server = rustPlatform.buildRustPackage (
    commonArgs
    // {
      buildFeatures = ["serve"] ++ pkgs.lib.optionals isDarwin ["metal"];
    }
  );

  docker = import ./docker.nix {
    inherit
      pkgs
      rustPlatform
      commonArgs
      rust-toolchain
      catgrad
      system
      server
      ;
    lib = pkgs.lib;
  };

  e2eTest = pkgs.writeShellApplication {
    name = "e2e-test";
    runtimeInputs = [server pkgs.coreutils pkgs.gnugrep pkgs.gawk];
    text = builtins.readFile ../tests/e2e.sh;
  };
in rec {
  packages =
    {
      default = cli;
      inherit cli server;
      "dep-hygiene" = depHygiene;
      "e2e-test" = e2eTest;
    }
    // docker.packages;

  apps =
    {
      "dep-hygiene" = {
        type = "app";
        program = "${depHygiene}/bin/dep-hygiene";
      };
      "e2e" = {
        type = "app";
        program = "${e2eTest}/bin/e2e-test";
      };
    }
    // docker.apps;

  devShells = rec {
    default = pkgs.mkShell {
      packages = devShellPackages;
    };

    # Explicit shell aliases so users can `nix develop .#server` / `.#server-cuda`
    # and still get a full development environment (not a package build env).
    server = default;

    cuda = pkgs.mkShell {
      packages = devShellPackages;
      nativeBuildInputs = docker.defaultCudaEnv.nativeBuildInputs;
      buildInputs = docker.defaultCudaEnv.buildInputs;
      inherit
        (docker.defaultCudaEnv)
        CUDA_COMPUTE_CAP
        CUDA_TOOLKIT_ROOT_DIR
        ;
      LD_LIBRARY_PATH = "${docker.defaultCudaEnv.runtimeLibraryPath}:${docker.defaultCudaEnv.driverLink}/lib";
    };

    "server-cuda" = cuda;
  };

  checks = import ./tests {
    inherit pkgs packages;
  };
}
