{
  self,
  system,
  nixpkgs,
  rust-overlay,
  catena-runner,
  exploratory-catena,
}:
let
  nativePkg = import ./package.nix {
    inherit
      self
      system
      nixpkgs
      rust-overlay
      catena-runner
      exploratory-catena
      ;
  };
  inherit (nativePkg)
    pkgs
    lib
    rustToolchain
    workspaceNativeBuildInputs
    ;

  cargoToolPackages = with pkgs; [
    cargo-audit
    cargo-deny
    cargo-fuzz
    cargo-llvm-cov
    cargo-mutants
    cargo-nextest
    cargo-outdated
    cargo-sort
    cargo-watch
  ];

  commonToolPackages = with pkgs; [
    jq
    just
    nixfmt
    taplo
  ];

  kernel = import ./kernel.nix {
    inherit
      pkgs
      lib
      rustToolchain
      cargoToolPackages
      commonToolPackages
      ;
  };

  devShellPackages =
    (with pkgs; [
      rustToolchain
      perl
      pkg-config
      protobuf
      llvmPackages.lld
      pre-commit
      protobuf-language-server
      gh
      cargo-machete
      cargo-udeps
      skopeo
    ])
    ++ cargoToolPackages
    ++ commonToolPackages;

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
  };

  ci = import ./ci.nix {
    inherit
      pkgs
      lib
      rustToolchain
      workspaceNativeBuildInputs
      ;
    extraChecks = kernel.checks;
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

  packagesFor =
    crossSystem:
    let
      pkgSpec = import ./package.nix {
        inherit
          self
          system
          nixpkgs
          rust-overlay
          catena-runner
          exploratory-catena
          crossSystem
          ;
      };
    in
    {
      cli = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        # Full network surface, but no local Catena runtime.
        buildFeatures = [
          "chain"
          "gateway"
        ]
        ++ lib.optionals (crossSystem == null) [
          "node"
          "otel"
        ];
      };
      cli-validator = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = [ "validator" ];
      };
    }
    # The current runner is HIP-only. Do not advertise a local Catena runtime
    # on platforms where its execution backend cannot work.
    //
      lib.optionalAttrs (crossSystem == null && pkgSpec.pkgs.stdenv.hostPlatform.system == "x86_64-linux")
        {
          cli-catena = pkgSpec.mkHellasPackage {
            buildNoDefaultFeatures = true;
            buildFeatures = [
              "evaluate"
              "otel"
            ];
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
  rocmPath = lib.optionalAttrs isX86_64Linux {
    path = pkgs.symlinkJoin {
      name = "hellas-rocm-path";
      paths = [
        pkgs.rocmPackages.clang
        pkgs.rocmPackages.clr
        pkgs.rocmPackages.hip-common
        pkgs.rocmPackages.hipcc
        pkgs.rocmPackages.rocm-core
        pkgs.rocmPackages.rocm-device-libs
        pkgs.rocmPackages.rocm-runtime
      ];
    };
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
          rustToolchain
          ;
        inherit (nativePackages) cli;
      };

      nixosTests = lib.optionalAttrs isX86_64Linux (
        import ./tests {
          inherit self pkgs lib;
          package = nativePackages.cli-catena;
          networkPackage = nativePackages.cli;
          validatorPackage = nativePackages.cli-validator;
        }
      );
    in
    {
      packages.docker = docker.image;

      apps."docker-push-all" = {
        type = "app";
        program = "${docker.push}/bin/docker-push";
        meta.description = "Push the Hellas network-node Docker image";
      };

      devShells = lib.optionalAttrs isX86_64Linux {
        rocm = pkgs.mkShellNoCC {
          packages = devShellPackages ++ [
            pkgs.rocmPackages.clang
            pkgs.rocmPackages.hipcc
          ];
          shellHook = envShellHook + ''
            export ROCM_PATH=${rocmPath.path}
            export HIP_PATH=${rocmPath.path}
            export HIP_CLANG_PATH=${pkgs.rocmPackages.clang}/bin
            export DEVICE_LIB_PATH=${pkgs.rocmPackages.rocm-device-libs}/amdgcn/bitcode
            export HIP_FLAGS="--rocm-path=${rocmPath.path} --rocm-device-lib-path=${pkgs.rocmPackages.rocm-device-libs}/amdgcn/bitcode"
            export LD_LIBRARY_PATH=${rocmPath.path}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
          '';
        };
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
      inputs = [ pkgs.nixfmt ];
      command = ''
        shopt -s globstar
        nixfmt --check flake.nix nix/**/*.nix
      '';
    };

    wasm-rpc = hellasRpcWasm;
  };

  hydraPackages = {
    inherit (nativePackages) cli cli-validator;
  }
  // lib.optionalAttrs isX86_64Linux {
    inherit (nativePackages) cli-catena;
    static-x86_64 = crossPackages.cross-x86_64-linux-musl-cli;
    static-aarch64 = crossPackages.cross-aarch64-linux-musl-cli;
    static-windows = crossPackages.cross-x86_64-windows-cli;
    inherit (linuxOutputs.packages) docker;
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
      "hellas-rpc-wasm" = hellasRpcWasm;
    }
    // (linuxOutputs.packages or { });

  apps = {
    check = {
      type = "app";
      program = lib.getExe ci.checkAll;
      meta.description = "Run local checks and dependency audits";
    };
    fix = {
      type = "app";
      program = lib.getExe ci.fixAll;
      meta.description = "Apply auto-fixes (fmt, sort, clippy)";
    };
  }
  // kernel.apps
  // (lib.mapAttrs' (
    name: pkg:
    lib.nameValuePair "check-${name}" {
      type = "app";
      program = lib.getExe pkg;
      meta.description = "Run the ${name} check";
    }
  ) ci.checks)
  // (linuxOutputs.apps or { });

  devShells = {
    default = defaultDevShell;
    kernel = kernel.devShell;
  }
  // (linuxOutputs.devShells or { });

  formatter = pkgs.nixfmt;

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
