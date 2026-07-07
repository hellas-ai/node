{
  pkgs,
  lib,
  mkHellasPackage,
  rustToolchain,
  catgrad,
  system,
  cliCandle,
}:
let
  imageRepository = "ghcr.io/hellas-ai/hellas";
  runtimeCoreLibs = with pkgs; [
    stdenv.cc.cc.lib
    glibc
  ];

  # Each variant maps to exactly one CUDA toolkit × SM architecture build.
  # bindgen_cuda compiles kernels for a single --gpu-architecture, so we need
  # one binary per target GPU generation.
  variants = [
    {
      cuda = pkgs.cudaPackages_12;
      sm = "80";
      tag = "cuda12-sm80";
    } # A100, A30
    {
      cuda = pkgs.cudaPackages_12;
      sm = "86";
      tag = "cuda12-sm86";
    } # RTX 3090/3080, A40
    {
      cuda = pkgs.cudaPackages_12;
      sm = "89";
      tag = "cuda12-sm89";
    } # RTX 4090/4080, L40S
    {
      cuda = pkgs.cudaPackages_13;
      sm = "89";
      tag = "cuda13-sm89";
    } # RTX 4090/4080, L40S
    {
      cuda = pkgs.cudaPackages_13;
      sm = "120";
      tag = "cuda13-sm120";
    } # RTX 5090/5080, Blackwell
  ];
  defaultTag = "cuda12-sm89";

  mkCudaEnv =
    v:
    catgrad.lib.${system}.mkCudaEnv {
      cudaPackages = v.cuda;
      cudaCapability = v.sm;
    };

  mkCliRuntime =
    {
      name,
      pkg,
      sourceBin,
    }:
    pkgs.runCommand name
      {
        nativeBuildInputs = [ pkgs.removeReferencesTo ];
      }
      ''
        mkdir -p "$out/bin"
        cp "${pkg}/bin/${sourceBin}" "$out/bin/hellas-cli"
        chmod u+w "$out/bin/hellas-cli"
        remove-references-to -t ${rustToolchain} "$out/bin/hellas-cli"
        chmod 0555 "$out/bin/hellas-cli"
      '';

  mkServerImage =
    {
      imageTag,
      runtimePkg,
      extraRuntimeContents ? [ ],
      cudaEnv ? null,
    }:
    pkgs.dockerTools.streamLayeredImage {
      name = imageRepository;
      tag = imageTag;
      contents = [
        runtimePkg
        pkgs.cacert
        pkgs.iana-etc
      ]
      ++ runtimeCoreLibs
      ++ extraRuntimeContents;
      config = {
        Entrypoint = [
          "${runtimePkg}/bin/hellas-cli"
          "serve"
        ];
        WorkingDir = "/var/lib/hellas";
        Volumes = {
          "/var/lib/hellas" = { };
        };
        ExposedPorts = {
          "31145/udp" = { };
        };
        Env = [
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

  cliCandleRuntime = mkCliRuntime {
    name = "hellas-cli-candle-runtime";
    pkg = cliCandle;
    sourceBin = "hellas-cli";
  };

  mkCudaImage =
    v:
    let
      cudaEnv = mkCudaEnv v;
      cliCuda = mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = [
          "chain"
          "candle-cuda"
        ];
        doCheck = false;
        nativeBuildInputs =
          (with pkgs.buildPackages; [
            pkg-config
            protobuf
            llvmPackages.lld
            makeWrapper
          ])
          ++ cudaEnv.nativeBuildInputs;
        inherit (cudaEnv) buildInputs;
        inherit (cudaEnv) CUDA_COMPUTE_CAP CUDA_TOOLKIT_ROOT_DIR;
        postInstall = ''
          for bin in $out/bin/*; do
            if [ -x "$bin" ] && [ ! -L "$bin" ]; then
              wrapProgram "$bin" \
                --prefix LD_LIBRARY_PATH : "${cudaEnv.runtimeLibraryPath}"
            fi
          done
        '';
      };
      runtime = mkCliRuntime {
        name = "hellas-cli-${v.tag}-runtime";
        pkg = cliCuda;
        sourceBin = ".hellas-cli-wrapped";
      };
    in
    {
      inherit cudaEnv;
      cli = cliCuda;
      image = mkServerImage {
        imageTag = v.tag;
        runtimePkg = runtime;
        extraRuntimeContents = cudaEnv.buildInputs;
        inherit cudaEnv;
      };
    };

  cudaImages = lib.listToAttrs (
    map (v: {
      name = v.tag;
      value = mkCudaImage v;
    }) variants
  );

  defaultCuda = cudaImages.${defaultTag};

  dockerImages = {
    cpu = mkServerImage {
      imageTag = "cpu";
      runtimePkg = cliCandleRuntime;
    };
  }
  // lib.mapAttrs (_: v: v.image) cudaImages;

  pushAll = pkgs.writeShellApplication {
    name = "docker-push-all";
    runtimeInputs = [ pkgs.skopeo ];
    text = lib.concatStringsSep "\n" (
      lib.mapAttrsToList (name: image: ''
        echo "pushing ${imageRepository}:${name}"
        ${image} | skopeo copy docker-archive:/dev/stdin "docker://${imageRepository}:${name}" "$@"
      '') dockerImages
    );
  };
  cudaCliPackages = lib.mapAttrs (_: v: v.cli) cudaImages;
  defaultCudaCli = defaultCuda.cli;
  defaultCudaImage = defaultCuda.image;
in
{
  defaultCudaEnv = defaultCuda.cudaEnv;
  inherit
    dockerImages
    pushAll
    cudaCliPackages
    defaultCudaCli
    defaultCudaImage
    ;
}
