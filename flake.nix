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

      rust-toolchain = pkgs.buildPackages.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatform = pkgs.makeRustPlatform {
        rustc = rust-toolchain;
        cargo = rust-toolchain;
      };

      commonArgs = {
        pname = "hellas";
        version = "0.1.0";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            # "catgrad-0.2.1" = "sha256-rlhwlUACdJyIlRg2jTA5nb2KcPQ+lCpWnhu68Z2idbM=";
          };
        };
        auditable = false;
        buildInputs = with pkgs; [openssl];
        nativeBuildInputs = with pkgs; [pkg-config protobuf];
        checkInputs = with pkgs; [cargo-deny cargo-outdated];
        separateDebugInfo = true;
        meta.mainProgram = "hellas-cli";
      };

      depHygiene = pkgs.writeShellApplication {
        name = "dep-hygiene";
        runtimeInputs = with pkgs; [
          rust-toolchain
          cargo-audit
          cargo-deny
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
            check        Run CI-oriented checks (major outdated, audit, deny, update dry-run)
            outdated     Print root dependency outdated report
            major        Fail if a root dependency has a newer major available
            audit        Run cargo audit
            deny         Run cargo deny checks (if deny.toml exists)
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
            out="$(cargo update --workspace --dry-run 2>&1 || true)"
            printf "%s\n" "$out"
            if printf "%s\n" "$out" | grep -Eq 'Locking [1-9][0-9]* packages?'; then
              echo "cargo update would modify Cargo.lock"
              return 1
            fi
            echo "Cargo.lock is up to date with cargo update --workspace"
          }

          run_deny() {
            if [ -f deny.toml ]; then
              cargo deny check advisories bans licenses sources
            else
              echo "deny.toml not found; skipping cargo deny"
            fi
          }

          case "$cmd" in
            check)
              status=0
              check_major || status=1
              cargo audit || status=1
              run_deny || status=1
              update_check || status=1
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
            deny)
              run_deny
              ;;
            update-check)
              update_check
              ;;
            update)
              cargo update --workspace
              ;;
            *)
              echo "unknown command: $cmd"
              usage
              exit 2
              ;;
          esac
        '';
      };

      cli = rustPlatform.buildRustPackage commonArgs;
      server = rustPlatform.buildRustPackage (commonArgs // {buildFeatures = ["serve"];});
    in {
      packages = {
        default = cli;
        inherit cli server;
        "dep-hygiene" = depHygiene;
      };

      apps = {
        "dep-hygiene" = {
          type = "app";
          program = "${depHygiene}/bin/dep-hygiene";
        };
      };

      overlays.default = final: _prev: {
        hellas = self.packages.${final.system}.cli;
        hellas-serve = self.packages.${final.system}.server;
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [self.packages.${system}.default];
        buildInputs = with pkgs; [
          pre-commit
          protobuf-language-server
          cargo-watch
          gh
          depHygiene
        ];
      };
    })
    // {
      nixosModules.hellas = {
        config,
        lib,
        pkgs,
        ...
      }: let
        inherit (lib) mkEnableOption mkIf mkOption types concatStringsSep;
        cfg = config.services.hellas;
        cliArgs = concatStringsSep " " (["serve"] ++ cfg.extraArgs);
      in {
        options.services.hellas = {
          enable = mkEnableOption "Hellas node server";
          package = mkOption {
            type = types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
            description = "Package providing the hellas CLI (with serve feature).";
          };
          discovery = mkOption {
            type = types.bool;
            default = true;
            description = "Deprecated option: discovery is always enabled by `hellas-cli serve`.";
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = "Open firewall port for the hellas node.";
          };
          port = mkOption {
            type = types.port;
            default = 31145;
            description = "Port for the hellas node to listen on.";
          };
          extraArgs = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Extra arguments to pass to `hellas-cli serve`.";
          };
        };

        config = mkIf cfg.enable {
          systemd.services.hellas = {
            description = "Hellas node server";
            wantedBy = ["multi-user.target"];
            after = ["network-online.target"];
            wants = ["network-online.target"];
            environment = {
              HOME = "/var/lib/hellas";
            };
            serviceConfig = {
              ExecStart = "${cfg.package}/bin/hellas-cli ${cliArgs}";
              Restart = "on-failure";
              DynamicUser = true;
              StateDirectory = "hellas";
              WorkingDirectory = "/var/lib/hellas";
            };
          };

          networking.firewall = mkIf cfg.openFirewall {
            allowedUDPPorts = [cfg.port];
          };
        };
      };

      nixosModules.default = self.nixosModules.hellas;
    };
}
