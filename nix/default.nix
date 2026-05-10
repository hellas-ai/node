{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catgrad,
}: let
  nativePkg = import ./package.nix {
    inherit self system nixpkgs rust-overlay;
  };
  inherit
    (nativePkg)
    pkgs
    lib
    rustToolchain
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

  # Internal shim that runs as the gateway-wrapped child for pi: reads the
  # gateway base URL from env (set by `gateway --wrap`), writes a one-shot
  # extension to a tempfile, exec's pi against it. Never in PATH; hellas-run
  # substitutes `pi` → this store path.
  piShim = pkgs.writeShellScript "hellas-pi-shim" ''
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
    (pkgs.writeShellScriptBin "hellas-run" ''
      # Usage:  hellas-run [--gw-flag=value...] CMD [CMD-ARGS...]
      # Leading flags (anything starting with `-`) go to `hellas-cli gateway`.
      # First positional is the wrapped command; the rest are its args.
      # Use `--flag=value` for gateway options that take a value.
      set -eu
      gw=()
      while [ $# -gt 0 ]; do
        case "$1" in -*) gw+=("$1"); shift ;; *) break ;; esac
      done
      [ $# -gt 0 ] || { echo "usage: hellas-run [--gw-flag=value...] CMD [args]" >&2; exit 2; }
      cmd="$1"; shift
      # `pi` doesn't honor *_BASE_URL env vars — route it through an internal
      # shim that runs inside the wrap and registers a hellas provider.
      case "$(basename "$cmd")" in pi) cmd=${piShim} ;; esac
      exec cargo run --quiet --features candle --bin hellas-cli -- gateway "''${gw[@]}" --wrap "$cmd" -- "$@"
    '')
  ];

  envShellHook = ''
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi
  '';

  ci = import ./ci.nix {
    inherit pkgs lib rustToolchain;
  };

  hfCaches = import ./tests/huggingface.nix {
    inherit pkgs lib;
  };

  packagesFor = crossSystem: let
    pkgSpec = import ./package.nix {
      inherit self system nixpkgs rust-overlay crossSystem;
    };
    hostPlatform = pkgSpec.pkgs.stdenv.hostPlatform;
  in
    {
      cli = pkgSpec.mkHellasPackage {
        buildInputs = [];
        doCheck = false;
      };
      cli-candle = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = ["candle"];
        doCheck = false;
      };
    }
    // lib.optionalAttrs hostPlatform.isDarwin {
      cli-candle-metal = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = ["candle-metal"];
        doCheck = false;
      };
    };

  crossTargets = {
    "aarch64-linux" = nixpkgs.lib.systems.examples.aarch64-multiplatform;
    "riscv64-linux" = nixpkgs.lib.systems.examples.riscv64;
    "x86_64-linux-musl" = nixpkgs.lib.systems.examples.musl64 // {isStatic = true;};
    "aarch64-linux-musl" = nixpkgs.lib.systems.examples.aarch64-multiplatform-musl // {isStatic = true;};
    "x86_64-windows" = nixpkgs.lib.systems.examples.mingwW64;
  };

  nativePackages = packagesFor null;
  crossOutputs = lib.mapAttrs (_: spec: packagesFor spec) crossTargets;

  linuxOutputs = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (let
    docker = import ./docker.nix {
      inherit pkgs lib rustToolchain catgrad system;
      mkHellasPackage = nativePkg.mkHellasPackage;
      cliCandle = nativePackages.cli-candle;
    };

    nixosTests = import ./tests {
      inherit self pkgs lib;
      package = nativePackages.cli-candle;
    };
  in {
    packages =
      {cli-candle-cuda = docker.defaultCudaCli;}
      // lib.mapAttrs' (name: value: lib.nameValuePair "docker-${name}" value) docker.dockerImages
      // lib.mapAttrs' (name: value: lib.nameValuePair "cli-candle-cuda-${name}" value) docker.cudaCliPackages;

    apps."docker-push-all" = {
      type = "app";
      program = "${docker.pushAll}/bin/docker-push-all";
    };

    devShells.cuda = pkgs.mkShell {
      packages = devShellPackages;
      shellHook = envShellHook;
      nativeBuildInputs = docker.defaultCudaEnv.nativeBuildInputs;
      buildInputs = docker.defaultCudaEnv.buildInputs;
      LD_LIBRARY_PATH = "${docker.defaultCudaEnv.runtimeLibraryPath}:${docker.defaultCudaEnv.driverLink}/lib";
      inherit (docker.defaultCudaEnv) CUDA_COMPUTE_CAP CUDA_TOOLKIT_ROOT_DIR;
    };

    inherit nixosTests;
  });
in {
  packages =
    nativePackages
    // {
      default = nativePackages.cli;
      cross = crossOutputs;
      "hf-cache-lfm2-350m" = hfCaches.lfm2_350MCache;
      "hf-cache-qwen3-0_6b" = hfCaches.qwen3_0_6BCache;
    }
    // (linuxOutputs.packages or {});

  apps =
    {
      check = {
        type = "app";
        program = "${ci.checkPackages.all}/bin/hellas-check-all";
        meta.description = "Run all CI checks (sort, fmt, clippy, outdated)";
      };
      fix = {
        type = "app";
        program = "${ci.fixPackages.all}/bin/hellas-fix-all";
        meta.description = "Apply all CI auto-fixes where supported";
      };
      # Individual `check-*` apps are what CI's matrix enumerates.
      check-fmt = {
        type = "app";
        program = "${ci.checkPackages.fmt}/bin/hellas-check-fmt";
      };
      check-clippy = {
        type = "app";
        program = "${ci.checkPackages.clippy}/bin/hellas-check-clippy";
      };
      check-sort = {
        type = "app";
        program = "${ci.checkPackages.sort}/bin/hellas-check-sort";
      };
      check-test = {
        type = "app";
        program = "${ci.testPackage}/bin/hellas-check-test";
      };
    }
    // (linuxOutputs.apps or {});

  devShells =
    {
      default = pkgs.mkShell {
        packages = devShellPackages;
        shellHook = envShellHook;
      };
    }
    // (linuxOutputs.devShells or {});

  # nixosTests are also surfaced under `checks` so `nix flake check` runs them.
  checks = linuxOutputs.nixosTests or {};
  nixosTests = linuxOutputs.nixosTests or {};
}
