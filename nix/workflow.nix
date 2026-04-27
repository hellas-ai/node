# Ok - so this file will demonstrate how to use hellas in a nix workflow

let
  models = {
    qwen_3_5 = {
      hf = "Qwen/Qwen3.5-0.5B";
    };
  };
in {
  story = hellas.mkInference {
    model = models.qwen_3_5;
    prompt = ''
      Use the 'write_file' tool to write a short haiku
    '';
  };
};


mkDerivation {

  buildPhase = ''
    ${hellas-cli.candle}/bin/cli --local --model ${models.qwen_3_5.hf} -p "use the 'write_file' tool to write a short haiku" to $out
  ''
}
