_: {
  apiFlavor = {
    anthropic = "anthropic-messages";
    openai = "openai-completions";
  };
  # Canonical executor UDP port. Matches `DEFAULT_PORT` in
  # `crates/cli/src/commands/serve/node.rs` and the `31145/udp` exposed by
  # the docker images.
  executorPort = 31145;
  # Default state directory for the Hellas serve daemon. Used by the NixOS
  # module as HOME / WorkingDirectory, and as the base for any documented
  # path examples.
  defaultStateDir = "/var/lib/hellas";
}
