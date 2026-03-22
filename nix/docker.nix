{
  pkgs,
  lib,
  rustPlatform,
  commonArgs,
  rust-toolchain,
  catgrad,
  system,
  server,
}: let
  imageRepository = "ghcr.io/hellas-ai/node";
  runtimeCoreLibs = with pkgs; [
    stdenv.cc.cc.lib
    openssl
    glibc
  ];

  # This matrix is constrained by both pinned nixpkgs and the vendored CUDA
  # support in the Rust stack. 12.4/12.5 are removed in nixpkgs here, and 13.2
  # is newer than the current cudarc support.
  defaultCudaVariant = "12-6";
  cudaVariantOrder = [
    "12-6"
    "13-1"
  ];
  cudaVariants = {
    "12-6" = pkgs.cudaPackages_12_6;
    "13-1" = pkgs.cudaPackages_13_1;
  };
  imageVersionFor = variantKey: lib.replaceStrings ["-"] ["."] variantKey;

  mkCudaEnv = cudaPackages:
    catgrad.lib.${system}.mkCudaEnv {inherit cudaPackages;};

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

  mkServerImage = {
    imageTag,
    runtimePkg,
    extraRuntimeContents ? [],
    cudaEnv ? null,
  }:
    pkgs.dockerTools.buildLayeredImage {
      name = imageRepository;
      tag = imageTag;
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
            "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
          ]
          ++ lib.optionals (cudaEnv != null) [
            "NVIDIA_VISIBLE_DEVICES=all"
            "NVIDIA_DRIVER_CAPABILITIES=compute,utility"
            "LD_LIBRARY_PATH=${cudaEnv.runtimeLibraryPath}:/usr/lib/x86_64-linux-gnu:/usr/lib64:/usr/local/nvidia/lib64"
          ];
      };
    };

  serverRuntime = mkServerRuntime {
    name = "hellas-server-runtime";
    pkg = server;
    sourceBin = "hellas-cli";
  };

  serverImage = mkServerImage {
    imageTag = "latest";
    runtimePkg = serverRuntime;
  };

  mkCudaArtifacts = variantKey: let
    cudaEnv = mkCudaEnv cudaVariants.${variantKey};
    imageVersion = imageVersionFor variantKey;
    serverCuda = rustPlatform.buildRustPackage (commonArgs
      // {
        buildFeatures = ["serve" "cuda"];
        nativeBuildInputs = commonArgs.nativeBuildInputs ++ [pkgs.makeWrapper] ++ cudaEnv.nativeBuildInputs;
        buildInputs = commonArgs.buildInputs ++ cudaEnv.buildInputs;
        CUDA_COMPUTE_CAP = cudaEnv.CUDA_COMPUTE_CAP;
        CUDA_TOOLKIT_ROOT_DIR = cudaEnv.CUDA_TOOLKIT_ROOT_DIR;
        doCheck = false;
        postInstall = ''
          for bin in $out/bin/*; do
            if [ -x "$bin" ] && [ ! -L "$bin" ]; then
              wrapProgram "$bin" \
                --prefix LD_LIBRARY_PATH : "${cudaEnv.runtimeLibraryPath}"
            fi
          done
        '';
      });
    serverCudaRuntime = mkServerRuntime {
      name = "hellas-server-cuda-${variantKey}-runtime";
      pkg = serverCuda;
      sourceBin = ".hellas-cli-wrapped";
    };
    serverCudaImage = mkServerImage {
      imageTag = "cuda-${imageVersion}";
      runtimePkg = serverCudaRuntime;
      extraRuntimeContents = cudaEnv.buildInputs;
      inherit cudaEnv;
    };
  in {
    inherit
      cudaEnv
      serverCuda
      serverCudaRuntime
      serverCudaImage
      ;
  };

  cudaArtifacts = lib.genAttrs cudaVariantOrder mkCudaArtifacts;
  defaultCudaArtifacts = cudaArtifacts.${defaultCudaVariant};
  defaultCudaImage = mkServerImage {
    imageTag = "cuda-latest";
    runtimePkg = defaultCudaArtifacts.serverCudaRuntime;
    extraRuntimeContents = defaultCudaArtifacts.cudaEnv.buildInputs;
    inherit (defaultCudaArtifacts) cudaEnv;
  };

  mergeAttrs = builtins.foldl' lib.recursiveUpdate {};

  versionedCudaPackages = mergeAttrs (
    map (variantKey: let
      artifacts = cudaArtifacts.${variantKey};
    in {
      "server-cuda-${variantKey}" = artifacts.serverCuda;
      "server-cuda-${variantKey}-runtime" = artifacts.serverCudaRuntime;
      "docker-server-cuda-${variantKey}" = artifacts.serverCudaImage;
    })
    cudaVariantOrder
  );

  dockerPush = pkgs.writeShellApplication {
    name = "docker-push";
    runtimeInputs = [pkgs.nix pkgs.docker pkgs.coreutils pkgs.gnused];
    text = ''
      set -euo pipefail

      usage() {
        cat <<'USAGE'
      Usage: docker-push <image-attr> <target-ref>

      Examples:
        docker-push docker-server ghcr.io/hellas-ai/node:latest
        docker-push docker-server-cuda ghcr.io/hellas-ai/node:cuda-latest
        docker-push docker-server-cuda-13-1 ghcr.io/hellas-ai/node:cuda-13.1

      Environment:
        HELLAS_FLAKE  Flake ref to build from (default: .)
      USAGE
      }

      if [ "$#" -ne 2 ]; then
        usage >&2
        exit 2
      fi

      image_attr="$1"
      target_ref="$2"
      flake_ref="''${HELLAS_FLAKE:-.}"

      image_tar="$(nix build --no-link --print-out-paths "$flake_ref#$image_attr")"
      load_output="$(docker load --input "$image_tar")"
      printf '%s\n' "$load_output"

      source_ref="$(printf '%s\n' "$load_output" | sed -n 's/^Loaded image: //p' | tail -n1)"
      if [ -z "$source_ref" ]; then
        echo "failed to determine loaded image reference from docker load output" >&2
        exit 1
      fi

      docker tag "$source_ref" "$target_ref"
      docker push "$target_ref"
    '';
  };

in {
  defaultCudaEnv = defaultCudaArtifacts.cudaEnv;

  packages =
    {
      "server-runtime" = serverRuntime;
      "docker-server" = serverImage;
      "server-cuda" = defaultCudaArtifacts.serverCuda;
      "server-cuda-runtime" = defaultCudaArtifacts.serverCudaRuntime;
      "docker-server-cuda" = defaultCudaImage;
    }
    // versionedCudaPackages;

  apps = {
    "docker-push" = {
      type = "app";
      program = "${dockerPush}/bin/docker-push";
    };
  };
}
