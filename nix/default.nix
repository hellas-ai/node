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
    perl
    pkg-config
    protobuf
    llvmPackages.lld
    pre-commit
    protobuf-language-server
    cargo-watch
    gh
    cargo-audit
    cargo-deny
    cargo-fuzz
    cargo-llvm-cov
    cargo-mutants
    cargo-nextest
    cargo-outdated
    cargo-sort
    cargo-machete
    cargo-udeps
    jq
    just
    nodejs_24
    skopeo
    stdenv.cc.cc.lib
    taplo
    temurin-bin
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

  defaultDevShell = pkgs.mkShell {
    packages = devShellPackages;
    shellHook = envShellHook;
    # Quint's Apalache backend dlopens libstdc++ through its bundled Z3.
    LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
  };

  ci = import ./ci.nix {
    inherit
      pkgs
      lib
      rustToolchain
      workspaceNativeBuildInputs
      ;
  };

  mkHydraSourceCheck =
    {
      name,
      inputs,
      command,
    }:
    pkgs.runCommand "hellas-${name}"
      {
        nativeBuildInputs = inputs;
      }
      ''
        export HOME="$TMPDIR/home"
        export XDG_CACHE_HOME="$TMPDIR/cache"
        mkdir -p "$HOME" "$XDG_CACHE_HOME"
        cd ${nativePkg.buildSrc}
        ${command}
        touch "$out"
      '';

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
  isX86_64Linux = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
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

  mkKernelModelApp =
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

  kernelModelTest = mkKernelModelApp {
    name = "hellas-kernel-model-test";
    npmScript = "quint:test";
  };

  kernelModelVerify = mkKernelModelApp {
    name = "hellas-kernel-model-verify";
    npmScript = "quint:verify";
    needsJvm = true;
  };

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

      nixosTests = lib.optionalAttrs isX86_64Linux (
        import ./tests {
          inherit self pkgs lib;
          package = nativePackages.cli-candle;
          inherit hellasRun;
        }
      );
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

  hydraLints = {
    sort = mkHydraSourceCheck {
      name = "check-sort";
      inputs = [ pkgs.cargo-sort ];
      command = "cargo-sort --workspace --check";
    };

    fmt = mkHydraSourceCheck {
      name = "check-fmt";
      inputs = [ rustToolchain ];
      command = "cargo fmt --all -- --check";
    };

    clippy = nativePkg.mkHellasPackage {
      pname = "hellas-check-clippy";
      cargoBuildType = "debug";
      buildPhase = ''
        runHook preBuild
        cargo clippy --workspace --all-targets --offline -- -D warnings
        runHook postBuild
      '';
      doCheck = false;
      installPhase = ''
        mkdir -p "$out"
        touch "$out/passed"
      '';
    };

    taplo = mkHydraSourceCheck {
      name = "check-taplo";
      inputs = [ pkgs.taplo ];
      command = "taplo fmt --option 'indent_string=    ' --check '*.toml' 'crates/**/Cargo.toml'";
    };

    buf = mkHydraSourceCheck {
      name = "check-buf";
      inputs = [ pkgs.buf ];
      command = "buf lint";
    };

    deadnix = mkHydraSourceCheck {
      name = "check-deadnix";
      inputs = [ pkgs.deadnix ];
      command = ''
        shopt -s globstar
        deadnix --fail flake.nix nix/**/*.nix
      '';
    };

    statix = mkHydraSourceCheck {
      name = "check-statix";
      inputs = [ pkgs.statix ];
      command = "statix check .";
    };

    nixfmt = mkHydraSourceCheck {
      name = "check-nixfmt";
      inputs = [ pkgs.nixfmt-rfc-style ];
      command = ''
        shopt -s globstar
        nixfmt --check flake.nix nix/**/*.nix
      '';
    };

    wasm-rpc = hellasRpcWasm;
  };

  hydraPackages = {
    inherit (nativePackages) cli cli-candle;
  }
  // lib.optionalAttrs isX86_64Linux {
    static-x86_64 = crossPackages.cross-x86_64-linux-musl-cli;
    static-aarch64 = crossPackages.cross-aarch64-linux-musl-cli;
    static-windows = crossPackages.cross-x86_64-windows-cli;
    inherit (linuxOutputs.packages) docker-cuda;
    "hellas-rpc-wasm" = hellasRpcWasm;
  };

  hydraE2e = linuxOutputs.nixosTests or { };

  hydraRequired = pkgs.releaseTools.aggregate {
    name = "hellas-required";
    constituents = [
      defaultDevShell
    ]
    ++ lib.attrValues hydraLints
    ++ lib.attrValues hydraPackages
    ++ lib.attrValues hydraE2e;
  };
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
    "check-kernel-models" = {
      type = "app";
      program = lib.getExe kernelModelTest;
      meta.description = "Run hellas-kernel Quint model tests";
    };
    "check-kernel-model-verify" = {
      type = "app";
      program = lib.getExe kernelModelVerify;
      meta.description = "Run hellas-kernel Quint model verification";
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
    default = defaultDevShell;
  }
  // (linuxOutputs.devShells or { });

  # Data exposed for local matrix runners:
  #   .checks -> { name -> derivation }
  #   .builds -> { name -> attrPath }
  ci = { inherit (ci) checks builds; };

  # nixosTests are also surfaced under `checks` so `nix flake check` runs them.
  checks = linuxOutputs.nixosTests or { };
  nixosTests = linuxOutputs.nixosTests or { };

  hydraJobs = {
    devShell = defaultDevShell;
    lints = hydraLints;
    packages = hydraPackages;
    required = hydraRequired;
  }
  // lib.optionalAttrs isX86_64Linux {
    e2e = hydraE2e;
  };
}
