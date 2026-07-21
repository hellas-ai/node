{
  pkgs,
  package,
}:
{
  basic =
    pkgs.runCommand "hellas-cli-basic"
      {
        nativeBuildInputs = with pkgs; [
          coreutils
          gnugrep
        ];
      }
      ''
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"

        ${package}/bin/hellas-cli --version
        ${package}/bin/hellas-cli --help | grep -F "Hellas node CLI"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--wrap"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--preload"

        ${package}/bin/hellas-cli --identity "$TMPDIR/identity" --software-root \
          monitor --timeout-secs 1 >/dev/null 2>&1 || true
        ${package}/bin/hellas-cli --identity "$TMPDIR/identity" identity show-node-id \
          | grep -E '^[0-9a-f]{64}$'

        touch "$out"
      '';
}
