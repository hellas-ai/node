{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}:
let
  nativePkg = import ./package.nix {
    inherit
      self
      system
      nixpkgs
      rust-overlay
      ;
  };
  inherit (nativePkg)
    pkgs
    lib
    rustToolchain
    workspaceNativeBuildInputs
    ;

  # Template for the pi provider extension. Substituted by piShim at runtime.
  piExtensionTemplate = pkgs.writeText "hellas-pi-extension.template.js" ''
    export default function (pi) {
      pi.registerProvider("hellas", {
        baseUrl: "@@BASE@@",
        apiKey: "unused",
        api: "@@API@@",
        models: [{
          id: "@@MODEL@@",
          name: "@@MODEL@@ (Hellas)",
          reasoning: false,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 32768,
          maxTokens: 2048,
        }],
      });
    }
  '';

  # Wrapper for running pi behind `hellas-cli gateway --wrap`. It reads the
  # gateway base URL from env (set by `--wrap`), writes a one-shot provider
  # extension, then execs pi against that provider.
  piShim = pkgs.writeShellApplication {
    name = "hellas-pi-shim";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnused
    ];
    text = ''
      set -eu
      model="''${HELLAS_MODEL:-Qwen/Qwen3-0.6B}"
      api="''${HELLAS_API:-anthropic-messages}"
      case "$api" in
        anthropic-messages) base="''${ANTHROPIC_BASE_URL:?ANTHROPIC_BASE_URL not set}" ;;
        openai-completions) base="''${OPENAI_BASE_URL:?OPENAI_BASE_URL not set}" ;;
        *) echo "hellas-pi-shim: unsupported HELLAS_API='$api'" >&2; exit 2 ;;
      esac
      ext=$(mktemp --suffix=.js -t hellas-pi-XXXXXX)
      sed -e "s|@@BASE@@|$base|g" -e "s|@@API@@|$api|g" -e "s|@@MODEL@@|$model|g" \
        ${piExtensionTemplate} > "$ext"
      export ANTHROPIC_API_KEY=unused OPENAI_API_KEY=unused
      exec ${pkgs.pi-coding-agent}/bin/pi -e "$ext" --provider hellas --model "$model" "$@"
    '';
  };

  piShimPath = pkgs.runCommand "hellas-pi-shim-path" { } ''
    mkdir -p "$out/bin"
    ln -s ${piShim}/bin/hellas-pi-shim "$out/bin/pi"
  '';

  mkHellasRun =
    { gatewayCommand }:
    pkgs.writeShellScriptBin "hellas-run" ''
      # Usage:  hellas-run [--gw-flag=value...] CMD [CMD-ARGS...]
      # Leading flags (anything starting with `-`) go to `hellas-cli gateway`.
      # First positional is the wrapped command; the rest are its args.
      # Use `--flag=value` for gateway options that take a value.
      set -eu
      export PATH="${piShimPath}/bin:$PATH"
      gw=()
      while [ $# -gt 0 ]; do
        case "$1" in -*) gw+=("$1"); shift ;; *) break ;; esac
      done
      [ $# -gt 0 ] || { echo "usage: hellas-run [--gw-flag=value...] CMD [args]" >&2; exit 2; }
      cmd="$1"; shift
      # `pi` doesn't honor *_BASE_URL env vars — route it through the packaged
      # shim that runs inside the wrap and registers a hellas provider.
      case "$(${pkgs.coreutils}/bin/basename "$cmd")" in pi) cmd=${piShim}/bin/hellas-pi-shim ;; esac
      exec ${gatewayCommand} "''${gw[@]}" --wrap "$cmd" -- "$@"
    '';

  hellasRunDev = mkHellasRun {
    gatewayCommand = "cargo run --quiet --features candle --bin hellas-cli -- gateway";
  };

  devShellPackages = with pkgs; [
    rustToolchain
    pkg-config
    protobuf
    llvmPackages.lld
    pre-commit
    protobuf-language-server
    cargo-watch
    gh
    cargo-audit
    cargo-outdated
    cargo-sort
    skopeo
    pi-coding-agent
    piShim
    hellasRunDev
  ];

  envShellHook = ''
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi
  '';

  ci = import ./ci.nix {
    inherit
      pkgs
      lib
      rustToolchain
      workspaceNativeBuildInputs
      ;
  };

  hfCaches = pkgs.hellasLib.hf;

  packagesFor =
    crossSystem:
    let
      pkgSpec = import ./package.nix {
        inherit
          self
          system
          nixpkgs
          rust-overlay
          crossSystem
          ;
      };
      inherit (pkgSpec.pkgs.stdenv) hostPlatform;
    in
    {
      cli = pkgSpec.mkHellasPackage {
        buildInputs = [ ];
      };
      cli-candle = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = [ "candle" ];
      };
    }
    // lib.optionalAttrs hostPlatform.isDarwin {
      cli-candle-metal = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = [ "candle-metal" ];
      };
    };

  crossTargets = {
    "aarch64-linux" = nixpkgs.lib.systems.examples.aarch64-multiplatform;
    "riscv64-linux" = nixpkgs.lib.systems.examples.riscv64;
    "x86_64-linux-musl" = nixpkgs.lib.systems.examples.musl64 // {
      isStatic = true;
    };
    "aarch64-linux-musl" = nixpkgs.lib.systems.examples.aarch64-multiplatform-musl // {
      isStatic = true;
    };
    "x86_64-windows" = nixpkgs.lib.systems.examples.mingwW64;
  };

  nativePackages = packagesFor null;
  hellasRun = mkHellasRun {
    gatewayCommand = "${nativePackages.cli-candle}/bin/hellas-cli gateway";
  };
  # Flat `cross-<target>-<name>` packages. Nested `packages.<sys>.cross.<target>.<name>`
  # violates the flake schema (each entry must be a derivation), which `nix flake check`
  # rightly flags.
  crossPackages = lib.concatMapAttrs (
    tgt: lib.mapAttrs' (name: pkg: lib.nameValuePair "cross-${tgt}-${name}" pkg)
  ) (lib.mapAttrs (_: packagesFor) crossTargets);

  # Wasm build of hellas-rpc. Native rustToolchain with an additional wasm32
  # target — not a nix crossSystem (that's for OS-level cross), just a rust
  # target. Output is whatever cargo produces in
  # `target/wasm32-unknown-unknown/release/` (rlib today; .wasm if/when the
  # crate adds `crate-type = ["cdylib"]`).
  hellasRpcWasm =
    let
      wasmRust = rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; };
      wasmPlatform = pkgs.makeRustPlatform {
        rustc = wasmRust;
        cargo = wasmRust;
        stdenv = pkgs.clangStdenv;
      };
    in
    wasmPlatform.buildRustPackage (
      nativePkg.commonArgs
      // {
        pname = "hellas-rpc-wasm";
        cargoBuildFlags = [
          "-p"
          "hellas-rpc"
        ];
        CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
        # wasm tests need wasm-bindgen-test infra (deferred). buildRustPackage's
        # canExecute heuristic doesn't see our CARGO_BUILD_TARGET override, so
        # without this it'd try to invoke `cargo test` against wasm and fail.
        doCheck = false;
      }
    );

  linuxOutputs = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
    let
      docker = import ./docker.nix {
        inherit
          pkgs
          lib
          rustToolchain
          catgrad
          system
          ;
        inherit (nativePkg) mkHellasPackage;
        cliCandle = nativePackages.cli-candle;
      };

      nixosTests = import ./tests {
        inherit self pkgs lib;
        package = nativePackages.cli-candle;
        inherit hellasRun;
      };
    in
    {
      packages = {
        cli-candle-cuda = docker.defaultCudaCli;
        docker-cuda = docker.defaultCudaImage;
      }
      // lib.mapAttrs' (name: value: lib.nameValuePair "docker-${name}" value) docker.dockerImages
      // lib.mapAttrs' (
        name: value: lib.nameValuePair "cli-candle-cuda-${name}" value
      ) docker.cudaCliPackages;

      apps."docker-push-all" = {
        type = "app";
        program = "${docker.pushAll}/bin/docker-push-all";
      };

      devShells.cuda = pkgs.mkShell {
        packages = devShellPackages;
        shellHook = envShellHook;
        inherit (docker.defaultCudaEnv) nativeBuildInputs;
        inherit (docker.defaultCudaEnv) buildInputs;
        inherit (docker.defaultCudaEnv) CUDA_COMPUTE_CAP CUDA_TOOLKIT_ROOT_DIR;
        LD_LIBRARY_PATH = "${docker.defaultCudaEnv.runtimeLibraryPath}:${docker.defaultCudaEnv.driverLink}/lib";
      };

      inherit nixosTests;
    }
  );
in
{
  packages =
    nativePackages
    // crossPackages
    // {
      default = nativePackages.cli;
      "hf-cache-lfm2-350m" = hfCaches.lfm2_350MCache;
      "hf-cache-qwen3-0_6b" = hfCaches.qwen3_0_6BCache;
      "hellas-pi-shim" = piShim;
      "hellas-run" = hellasRun;
      "hellas-rpc-wasm" = hellasRpcWasm;
    }
    // (linuxOutputs.packages or { });

  apps = {
    check = {
      type = "app";
      program = lib.getExe ci.checkAll;
      meta.description = "Run all CI checks (sort, fmt, clippy, test, wasm-rpc, outdated)";
    };
    fix = {
      type = "app";
      program = lib.getExe ci.fixAll;
      meta.description = "Apply auto-fixes (fmt, sort, clippy)";
    };
  }
  // (lib.mapAttrs' (
    name: pkg:
    lib.nameValuePair "check-${name}" {
      type = "app";
      program = lib.getExe pkg;
    }
  ) ci.checks)
  // (linuxOutputs.apps or { });

  devShells = {
    default = pkgs.mkShell {
      packages = devShellPackages;
      shellHook = envShellHook;
    };
  }
  // (linuxOutputs.devShells or { });

  # Data exposed for the GitHub Actions matrix:
  #   .checks → { name → derivation }  (workflow uses `attrNames`)
  #   .builds → { name → attrPath }    (extended post-gate builds)
  ci = { inherit (ci) checks builds; };

  # nixosTests are also surfaced under `checks` so `nix flake check` runs them.
  checks = linuxOutputs.nixosTests or { };
  nixosTests = linuxOutputs.nixosTests or { };
}
