{
  pkgs,
  lib,
}: rec {
  # Build a HuggingFace-shaped cache directory. `files` is an attrset mapping
  # in-snapshot file name → SRI hash; we fetch each one and symlink it into
  # the snapshot tree so HF_HOME=<out> behaves like a populated hub cache.
  mkHuggingFaceCache = {
    name,
    repo,
    revision,
    files,
    ref ? "main",
  }: let
    repoPath = "models--${lib.replaceStrings ["/"] ["--"] repo}";
    snapshotPath = "$out/hub/${repoPath}/snapshots/${revision}";
    fetchFile = file: hash:
      pkgs.fetchurl {
        url = "https://huggingface.co/${repo}/resolve/${revision}/${file}";
        sha256 = hash;
      };
    linkCommands = lib.concatStringsSep "\n" (lib.mapAttrsToList (file: hash: ''
        ln -s ${fetchFile file hash} "${snapshotPath}/${file}"
      '')
      files);
  in
    pkgs.runCommand name {
      # Output is just symlinks to fetchurl FOD paths, byte-identical across
      # systems. CA derivation → store path derived from the NAR hash, so a
      # cache built on Linux substitutes cleanly into a Darwin closure.
      __contentAddressed = true;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
    } ''
      mkdir -p "$out/hub/${repoPath}/refs" "${snapshotPath}"
      printf '%s' '${revision}' > "$out/hub/${repoPath}/refs/${ref}"
      ${linkCommands}
    '';

  lfm2_350MCache = mkHuggingFaceCache {
    name = "hf-cache-lfm2-350m";
    repo = "LiquidAI/LFM2-350M";
    revision = "b29be27ca6f2a4f5523cd9efbfd4c6caa3951d36";
    files = {
      "config.json" = "sha256-/Ts/uk5Q57miK9QcurWemyjjGbLeGWaNf9l3fI0am6E=";
      "model.safetensors" = "sha256-OHY43Iif8aE5XDwquWBSEeTH4W8tN1Nh3U5CO5CaJU4=";
      "special_tokens_map.json" = "sha256-dCrv4rfexJboyv/boDp10MGpkl1TvT8+DTiMlrWRtvQ=";
      "tokenizer.json" = "sha256-mM/4O09tfp2JKb68YrB+ks8bP5nIDRa6/ouEp1RI9As=";
      "tokenizer_config.json" = "sha256-Y87Y7oYn+ksGOMTAVzUfAPtOMyyiMnqaAO7MWXjoSDU=";
      "chat_template.jinja" = "sha256-zvGHQA1ipZUHqrOmQuqajSou8mNWK8NDBWDhFpRSc88=";
    };
  };

  qwen3_0_6BCache = mkHuggingFaceCache {
    name = "hf-cache-qwen3-0_6b";
    repo = "Qwen/Qwen3-0.6B";
    revision = "c1899de289a04d12100db370d81485cdf75e47ca";
    files = {
      "config.json" = "sha256-Zg2ztz14gRnARTXkjPm+X1W8MQCEGnGGN65pW0QvJ90=";
      "model.safetensors" = "sha256-9H9xF38yvNEBt1c+yRcealf09NMRSNOOOCMG9CmWh0s=";
      "tokenizer.json" = "sha256-rrEzB6cazY/oGGHZStVKtonfdzMYgJ7tPL55S0SS2uQ=";
      "tokenizer_config.json" = "sha256-1dCfB7SMMIbFCLMNHJEUvRGJFFt06YKiZTUMkjrNgQE=";
    };
  };
}
