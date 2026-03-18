{
  description = "Hellas Node";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    catgrad = {
      url = "github:hellas-ai/catgrad";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    catgrad,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
        config.allowUnfree = true;
      };
      # Override catgrad's CUDA defaults (RunPod drivers don't support CUDA 13 yet)
      catgradCudaEnv = catgrad.lib.${system}.mkCudaEnv {
        cudaPackages = pkgs.cudaPackages_12_6;
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
        postPatch = ''
          ln -sfn ${catgrad} ../catgrad
        '';
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "catgrad-0.2.1" = pkgs.lib.fakeHash;
          };
        };
        auditable = false;
        buildInputs = with pkgs; [openssl];
        nativeBuildInputs = with pkgs; [pkg-config protobuf llvmPackages.lld];
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
      serverCuda = rustPlatform.buildRustPackage (commonArgs
        // {
          buildFeatures = ["serve" "cuda"];
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [pkgs.makeWrapper] ++ catgradCudaEnv.nativeBuildInputs;
          buildInputs = commonArgs.buildInputs ++ catgradCudaEnv.buildInputs;
          CUDA_COMPUTE_CAP = catgradCudaEnv.CUDA_COMPUTE_CAP;
          CUDA_TOOLKIT_ROOT_DIR = catgradCudaEnv.CUDA_TOOLKIT_ROOT_DIR;
          doCheck = false;
          postInstall = ''
            for bin in $out/bin/*; do
              if [ -x "$bin" ] && [ ! -L "$bin" ]; then
                wrapProgram "$bin" \
                  --prefix LD_LIBRARY_PATH : "${catgradCudaEnv.runtimeLibraryPath}"
              fi
            done
          '';
        });

      runtimeCoreLibs = with pkgs; [
        stdenv.cc.cc.lib
        openssl
        glibc
      ];

      mkServerRuntime = {
        name,
        pkg,
        sourceBin,
      }:
        pkgs.runCommand name {
          nativeBuildInputs = [pkgs.removeReferencesTo];
        } ''
          mkdir -p "$out/bin"
          cp "${pkg}/bin/${sourceBin}" "$out/bin/hellas-cli"
          chmod u+w "$out/bin/hellas-cli"

          # Rust std source paths can keep a rust toolchain reference alive in the runtime closure.
          remove-references-to -t ${rust-toolchain} "$out/bin/hellas-cli"

          chmod 0555 "$out/bin/hellas-cli"
        '';

      serverRuntime = mkServerRuntime {
        name = "hellas-server-runtime";
        pkg = server;
        sourceBin = "hellas-cli";
      };

      serverCudaRuntime = mkServerRuntime {
        name = "hellas-server-cuda-runtime";
        pkg = serverCuda;
        sourceBin = ".hellas-cli-wrapped";
      };

      mkServerImage = {
        imageName,
        runtimePkg,
        extraRuntimeContents ? [],
        cuda ? false,
      }:
        pkgs.dockerTools.buildLayeredImage {
          name = imageName;
          tag = "latest";
          contents =
            [
              runtimePkg
              pkgs.cacert
              pkgs.iana-etc
            ]
            ++ runtimeCoreLibs ++ extraRuntimeContents;
          config = {
            Entrypoint = ["${runtimePkg}/bin/hellas-cli" "serve"];
            WorkingDir = "/var/lib/hellas";
            Volumes = {"/var/lib/hellas" = {};};
            ExposedPorts = {"31145/udp" = {};};
            Env =
              [
                "HOME=/home/hellas"
                "HF_HOME=/home/hellas/.cache/huggingface"
                "HF_HUB_CACHE=/home/hellas/.cache/huggingface/hub"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ]
              ++ pkgs.lib.optionals cuda [
                "NVIDIA_VISIBLE_DEVICES=all"
                "NVIDIA_DRIVER_CAPABILITIES=compute,utility"
                "LD_LIBRARY_PATH=${catgradCudaEnv.runtimeLibraryPath}:/usr/lib/x86_64-linux-gnu:/usr/lib64:/usr/local/nvidia/lib64"
              ];
          };
        };

      serverImage = mkServerImage {
        imageName = "hellas-server";
        runtimePkg = serverRuntime;
      };

      serverCudaImage = mkServerImage {
        imageName = "hellas-server-cuda";
        runtimePkg = serverCudaRuntime;
        extraRuntimeContents = catgradCudaEnv.buildInputs;
        cuda = true;
      };

      dockerRunServer = pkgs.writeShellApplication {
        name = "hellas-docker-run-server";
        runtimeInputs = [pkgs.docker pkgs.coreutils];
        text = ''
          set -euo pipefail

          usage() {
            cat <<'USAGE'
          Usage: hellas-docker-run-server [--config <path>]

          Config file format: shell env assignments, e.g.
            HELLAS_PORT=31145
            HELLAS_CONTAINER_NAME=hellas-server
            HELLAS_HF_CACHE_DIR=$HOME/.cache/huggingface
            HELLAS_DATA_DIR=$HOME/.local/share/hellas
            HELLAS_DOCKER_USER=1000:100
            HELLAS_DOWNLOAD_POLICY=eager
            HELLAS_EXECUTE_POLICY=eager
            HELLAS_LOG=info
          USAGE
          }

          config_file="''${HELLAS_CONFIG_FILE:-}"
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --config)
                [ "$#" -ge 2 ] || { echo "--config requires a path" >&2; exit 2; }
                config_file="$2"
                shift 2
                ;;
              -h|--help)
                usage
                exit 0
                ;;
              --)
                shift
                break
                ;;
              *)
                echo "unknown argument: $1" >&2
                usage
                exit 2
                ;;
            esac
          done

          if [ -n "$config_file" ]; then
            [ -f "$config_file" ] || { echo "config file not found: $config_file" >&2; exit 1; }
            set -a
            # shellcheck disable=SC1090
            . "$config_file"
            set +a
          fi

          image_tar="${serverImage}"
          image_ref="hellas-server:latest"
          name="''${HELLAS_CONTAINER_NAME:-hellas-server}"
          port="''${HELLAS_PORT:-31145}"
          hf_cache="''${HELLAS_HF_CACHE_DIR:-$HOME/.cache/huggingface}"
          data_dir="''${HELLAS_DATA_DIR:-$HOME/.local/share/hellas}"
          run_user="''${HELLAS_DOCKER_USER:-$(id -u):$(id -g)}"
          download_policy="''${HELLAS_DOWNLOAD_POLICY:-}"
          execute_policy="''${HELLAS_EXECUTE_POLICY:-}"
          log_level="''${HELLAS_LOG:-warn}"

          mkdir -p "$hf_cache" "$data_dir"
          docker load < "$image_tar" >/dev/null
          docker rm -f "$name" >/dev/null 2>&1 || true

          server_args=(--port "$port")
          if [ -n "$download_policy" ]; then
            server_args+=(--download-policy "$download_policy")
          fi
          if [ -n "$execute_policy" ]; then
            server_args+=(--execute-policy "$execute_policy")
          fi

          docker run -d \
            --name "$name" \
            --restart unless-stopped \
            --user "$run_user" \
            -e HOME=/home/hellas \
            -e HF_HOME=/home/hellas/.cache/huggingface \
            -e HF_HUB_CACHE=/home/hellas/.cache/huggingface/hub \
            -e RUST_LOG="$log_level" \
            -v "$hf_cache":/home/hellas/.cache/huggingface \
            -v "$data_dir":/var/lib/hellas \
            -p "$port":"$port"/udp \
            "$image_ref" "''${server_args[@]}"

          docker ps --filter "name=$name" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        '';
      };

      dockerRunServerCuda = pkgs.writeShellApplication {
        name = "hellas-docker-run-server-cuda";
        runtimeInputs = [pkgs.docker pkgs.coreutils];
        text = ''
          set -euo pipefail

          usage() {
            cat <<'USAGE'
          Usage: hellas-docker-run-server-cuda [--config <path>]

          Config file format: shell env assignments, e.g.
            HELLAS_PORT=31145
            HELLAS_CONTAINER_NAME=hellas-server-cuda
            HELLAS_HF_CACHE_DIR=$HOME/.cache/huggingface
            HELLAS_DATA_DIR=$HOME/.local/share/hellas
            HELLAS_DOCKER_USER=1000:100
            HELLAS_DOWNLOAD_POLICY=eager
            HELLAS_EXECUTE_POLICY=eager
            HELLAS_LOG=info
          USAGE
          }

          config_file="''${HELLAS_CONFIG_FILE:-}"
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --config)
                [ "$#" -ge 2 ] || { echo "--config requires a path" >&2; exit 2; }
                config_file="$2"
                shift 2
                ;;
              -h|--help)
                usage
                exit 0
                ;;
              --)
                shift
                break
                ;;
              *)
                echo "unknown argument: $1" >&2
                usage
                exit 2
                ;;
            esac
          done

          if [ -n "$config_file" ]; then
            [ -f "$config_file" ] || { echo "config file not found: $config_file" >&2; exit 1; }
            set -a
            # shellcheck disable=SC1090
            . "$config_file"
            set +a
          fi

          image_tar="${serverCudaImage}"
          image_ref="hellas-server-cuda:latest"
          name="''${HELLAS_CONTAINER_NAME:-hellas-server-cuda}"
          port="''${HELLAS_PORT:-31145}"
          hf_cache="''${HELLAS_HF_CACHE_DIR:-$HOME/.cache/huggingface}"
          data_dir="''${HELLAS_DATA_DIR:-$HOME/.local/share/hellas}"
          run_user="''${HELLAS_DOCKER_USER:-$(id -u):$(id -g)}"
          download_policy="''${HELLAS_DOWNLOAD_POLICY:-}"
          execute_policy="''${HELLAS_EXECUTE_POLICY:-}"
          log_level="''${HELLAS_LOG:-warn}"

          mkdir -p "$hf_cache" "$data_dir"
          docker load < "$image_tar" >/dev/null
          docker rm -f "$name" >/dev/null 2>&1 || true

          server_args=(--port "$port")
          if [ -n "$download_policy" ]; then
            server_args+=(--download-policy "$download_policy")
          fi
          if [ -n "$execute_policy" ]; then
            server_args+=(--execute-policy "$execute_policy")
          fi

          docker run -d \
            --name "$name" \
            --restart unless-stopped \
            --device=nvidia.com/gpu=all \
            --user "$run_user" \
            -e HOME=/home/hellas \
            -e HF_HOME=/home/hellas/.cache/huggingface \
            -e HF_HUB_CACHE=/home/hellas/.cache/huggingface/hub \
            -e RUST_LOG="$log_level" \
            -v "$hf_cache":/home/hellas/.cache/huggingface \
            -v "$data_dir":/var/lib/hellas \
            -p "$port":"$port"/udp \
            "$image_ref" "''${server_args[@]}"

          docker ps --filter "name=$name" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        '';
      };

      e2eTest = pkgs.writeShellApplication {
        name = "e2e-test";
        runtimeInputs = [server pkgs.coreutils pkgs.gnugrep pkgs.gawk];
        text = builtins.readFile ./tests/e2e.sh;
      };

      catgradShells = catgrad.devShells.${system} or {};
      catgradCudaShell =
        if catgradShells ? cuda
        then catgradShells.cuda
        else if catgradShells ? default
        then catgradShells.default
        else throw "catgrad flake has no devShells.${system}.cuda";
    in {
      packages = {
        default = cli;
        inherit
          cli
          server
          serverCuda
          serverRuntime
          serverCudaRuntime
          serverImage
          serverCudaImage
          dockerRunServer
          dockerRunServerCuda
          ;
        "server-cuda" = serverCuda;
        "server-runtime" = serverRuntime;
        "server-cuda-runtime" = serverCudaRuntime;
        "docker-server" = serverImage;
        "docker-server-cuda" = serverCudaImage;
        "docker-run-server" = dockerRunServer;
        "docker-run-server-cuda" = dockerRunServerCuda;
        "dep-hygiene" = depHygiene;
        "e2e-test" = e2eTest;
      };

      apps = {
        "dep-hygiene" = {
          type = "app";
          program = "${depHygiene}/bin/dep-hygiene";
        };
        "e2e" = {
          type = "app";
          program = "${e2eTest}/bin/e2e-test";
        };
        "docker-run-server" = {
          type = "app";
          program = "${dockerRunServer}/bin/hellas-docker-run-server";
        };
        "docker-run-server-cuda" = {
          type = "app";
          program = "${dockerRunServerCuda}/bin/hellas-docker-run-server-cuda";
        };
      };

      overlays.default = final: _prev: {
        hellas = self.packages.${final.system}.cli;
        hellas-serve = self.packages.${final.system}.server;
      };

      devShells = rec {
        default = pkgs.mkShell {
          inputsFrom = [self.packages.${system}.default];
          buildInputs = with pkgs; [
            pre-commit
            protobuf-language-server
            cargo-watch
            gh
            depHygiene
            llvmPackages.lld
            skopeo
          ];
        };

        # Explicit shell aliases so users can `nix develop .#server` / `.#server-cuda`
        # and still get a full development environment (not a package build env).
        server = default;

        cuda = pkgs.mkShell {
          inputsFrom = [
            default
            catgradCudaShell
          ];
          LD_LIBRARY_PATH = "${catgradCudaEnv.runtimeLibraryPath}:${catgradCudaEnv.driverLink}/lib";
        };

        "server-cuda" = cuda;
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
        cliArgs = concatStringsSep " " (
          ["serve"]
          ++ lib.optionals (cfg.port != null) ["--port" (toString cfg.port)]
          ++ lib.optionals (cfg.downloadPolicy != null) ["--download-policy" cfg.downloadPolicy]
          ++ lib.optionals (cfg.executePolicy != null) ["--execute-policy" cfg.executePolicy]
          ++ cfg.extraArgs
        );
      in {
        options.services.hellas = {
          enable = mkEnableOption "Hellas node server";
          package = mkOption {
            type = types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
            description = "Package providing the hellas CLI (with serve feature).";
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = "Open firewall port for the hellas node.";
          };
          port = mkOption {
            type = types.nullOr types.port;
            default = null;
            description = "Port for the hellas node to listen on. Null (default) auto-selects.";
          };
          downloadPolicy = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              Model download policy.
              "skip" (CLI default) never downloads (cache-only),
              "eager" downloads any requested model,
              "allow(pattern,...)" downloads only matching HF model patterns.
            '';
          };
          executePolicy = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              Graph execution policy.
              "skip" (CLI default) refuses all executions,
              "eager" executes any graph,
              "allow(hf/pattern,...,graph/pattern,...)" executes only matching.
            '';
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

          networking.firewall = mkIf (cfg.openFirewall && cfg.port != null) {
            allowedUDPPorts = [cfg.port];
          };
        };
      };

      nixosModules.default = self.nixosModules.hellas;
    };
}
