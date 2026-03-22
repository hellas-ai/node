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
  runtimeCoreLibs = with pkgs; [stdenv.cc.cc.lib openssl glibc];

  # Each variant maps to exactly one CUDA toolkit × SM architecture build.
  # bindgen_cuda compiles kernels for a single --gpu-architecture, so we need
  # one binary per target GPU generation.
  #
  # CUDA 12: broad driver compat, covers Ampere–Ada   (sm80–sm89)
  # CUDA 13: required for Blackwell+                   (sm100+)
  variants = [
    {cuda = pkgs.cudaPackages_12; sm = "80"; tag = "sm80";}   # A100, A30
    {cuda = pkgs.cudaPackages_12; sm = "86"; tag = "sm86";}   # RTX 3090/3080, A40
    {cuda = pkgs.cudaPackages_12; sm = "89"; tag = "sm89";}   # RTX 4090/4080, L40S
    {cuda = pkgs.cudaPackages_13; sm = "120"; tag = "sm120";} # RTX 5090/5080, Blackwell
  ];
  defaultTag = "sm89";

  mkCudaEnv = v:
    catgrad.lib.${system}.mkCudaEnv {
      cudaPackages = v.cuda;
      cudaCapability = v.sm;
    };

  mkServerRuntime = {name, pkg, sourceBin}:
    pkgs.runCommand name {
      nativeBuildInputs = [pkgs.removeReferencesTo];
    } ''
      mkdir -p "$out/bin"
      cp "${pkg}/bin/${sourceBin}" "$out/bin/hellas-cli"
      chmod u+w "$out/bin/hellas-cli"
      remove-references-to -t ${rust-toolchain} "$out/bin/hellas-cli"
      chmod 0555 "$out/bin/hellas-cli"
    '';

  mkServerImage = {imageTag, runtimePkg, extraRuntimeContents ? [], cudaEnv ? null}:
    pkgs.dockerTools.buildLayeredImage {
      name = imageRepository;
      tag = imageTag;
      contents = [runtimePkg pkgs.cacert pkgs.iana-etc] ++ runtimeCoreLibs ++ extraRuntimeContents;
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

  mkCudaArtifacts = v: let
    cudaEnv = mkCudaEnv v;
    serverCuda = rustPlatform.buildRustPackage (commonArgs // {
      buildFeatures = ["serve" "cuda"];
      nativeBuildInputs = commonArgs.nativeBuildInputs ++ [pkgs.makeWrapper] ++ cudaEnv.nativeBuildInputs;
      buildInputs = commonArgs.buildInputs ++ cudaEnv.buildInputs;
      inherit (cudaEnv) CUDA_COMPUTE_CAP CUDA_TOOLKIT_ROOT_DIR;
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
    runtime = mkServerRuntime {
      name = "hellas-server-${v.tag}-runtime";
      pkg = serverCuda;
      sourceBin = ".hellas-cli-wrapped";
    };
    image = mkServerImage {
      imageTag = "${v.tag}-latest";
      runtimePkg = runtime;
      extraRuntimeContents = cudaEnv.buildInputs;
      inherit cudaEnv;
    };
  in {
    inherit cudaEnv;
    packages = {
      "server-${v.tag}" = serverCuda;
      "server-${v.tag}-runtime" = runtime;
      "docker-server-${v.tag}" = image;
    };
  };

  allCuda = map mkCudaArtifacts variants;
  defaultCuda = mkCudaArtifacts (lib.findFirst (v: v.tag == defaultTag) (builtins.head variants) variants);

  dockerPush = pkgs.writeShellApplication {
    name = "docker-push";
    runtimeInputs = [pkgs.nix pkgs.docker pkgs.coreutils pkgs.gnused];
    text = ''
      set -euo pipefail
      usage() {
        cat <<'USAGE'
      Usage: docker-push <image-attr> <target-ref>

      Examples:
        docker-push docker-server   ghcr.io/hellas-ai/node:latest
        docker-push docker-server-cuda ghcr.io/hellas-ai/node:cuda-latest
        docker-push docker-server-sm86 ghcr.io/hellas-ai/node:sm86-latest

      Environment:
        HELLAS_FLAKE  Flake ref to build from (default: .)
      USAGE
      }
      if [ "$#" -ne 2 ]; then usage >&2; exit 2; fi
      image_attr="$1"; target_ref="$2"
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
  defaultCudaEnv = defaultCuda.cudaEnv;

  packages =
    {
      "server-runtime" = serverRuntime;
      "docker-server" = serverImage;
      "server-cuda" = defaultCuda.packages."server-${defaultTag}";
      "server-cuda-runtime" = defaultCuda.packages."server-${defaultTag}-runtime";
      "docker-server-cuda" = mkServerImage {
        imageTag = "cuda-latest";
        runtimePkg = defaultCuda.packages."server-${defaultTag}-runtime";
        extraRuntimeContents = defaultCuda.cudaEnv.buildInputs;
        cudaEnv = defaultCuda.cudaEnv;
      };
    }
    // lib.foldl' lib.recursiveUpdate {} (map (a: a.packages) allCuda);

  apps = {
    "docker-push" = {
      type = "app";
      program = "${dockerPush}/bin/docker-push";
    };
  };
}
