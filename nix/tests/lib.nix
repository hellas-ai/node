{pkgs, lib}: let
  mkHuggingFaceCache = {
    name,
    repo,
    revision,
    files,
    ref ? "main",
  }: let
    repoPath = "models--${lib.replaceStrings ["/"] ["--"] repo}";
    snapshotPath = "$out/hub/${repoPath}/snapshots/${revision}";
    linkCommands = lib.concatStringsSep "\n" (
      lib.mapAttrsToList (fileName: src: ''
        ln -s ${src} "${snapshotPath}/${fileName}"
      '') files
    );
  in
    pkgs.runCommand name {} ''
      mkdir -p "$out/hub/${repoPath}/refs" "${snapshotPath}"
      printf '%s' '${revision}' > "$out/hub/${repoPath}/refs/${ref}"
      ${linkCommands}
    '';

  smolLm2InstructRevision = "12fd25f77366fa6b3b4b768ec3050bf629380bac";
  smolLm2InstructRepo = "HuggingFaceTB/SmolLM2-135M-Instruct";
  fetchSmolLm2File = file: hash:
    pkgs.fetchurl {
      url = "https://huggingface.co/${smolLm2InstructRepo}/resolve/${smolLm2InstructRevision}/${file}";
      sha256 = hash;
    };

  smolLm2InstructCache = mkHuggingFaceCache {
    name = "hf-cache-smollm2-135m-instruct";
    repo = smolLm2InstructRepo;
    revision = smolLm2InstructRevision;
    files = {
      "config.json" = fetchSmolLm2File "config.json" "sha256-jrdA6Lvkz/lep7RYjReiQy3rFugHW8WCj/e6m+lNmCo=";
      "merges.txt" = fetchSmolLm2File "merges.txt" "sha256-C1Toqk5T1Tg+LkvGNaVrQ/lkf3sTgy1dns2PgtrE9RA=";
      "model.safetensors" = fetchSmolLm2File "model.safetensors" "sha256-WvVxy/B05tIaA1KNIzB5LlMspgjySscKFD9rNploq4w=";
      "special_tokens_map.json" = fetchSmolLm2File "special_tokens_map.json" "sha256-K3N5866BNSkoGlxgK8WhHB1OCpkQeqpZf+k2wegTylI=";
      "tokenizer.json" = fetchSmolLm2File "tokenizer.json" "sha256-nKms3bZSWhlOyKx6h/JPu6cjKpoV/6GvDBIk/NiI5Hw=";
      "tokenizer_config.json" = fetchSmolLm2File "tokenizer_config.json" "sha256-Tsd9RPYu/rONfgRKHbMY9qk5Q4QlMS36MzuDgtutmN8=";
      "vocab.json" = fetchSmolLm2File "vocab.json" "sha256-grhAEuOt1NAdEroURCAm5JuMu66tH3ns89kZeE+C3Hk=";
    };
  };
in {
  inherit mkHuggingFaceCache smolLm2InstructCache;
}
