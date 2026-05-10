{
  pkgs,
  lib,
  rustToolchain,
}: let
  # Single source of truth for CI lint/test commands. Each entry has:
  #   check — read-only verification command (run by CI, `nix run .#check`)
  #   fix   — optional auto-apply variant (run by `nix run .#fix`)
  # `nix eval .#ci.<system>.commands` returns { name → check } and is
  # what the GitHub Actions matrix enumerates.
  ciChecks = {
    fmt = {
      check = "cargo fmt --all -- --check";
      fix = "cargo fmt --all";
    };
    clippy = {
      check = "cargo clippy --workspace --all-targets -- -D warnings";
      fix = "cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged";
    };
    sort = {
      check = "cargo-sort --workspace --check";
      fix = "cargo-sort --workspace";
    };
    test = {
      check = "cargo test --workspace";
    };
  };

  # Heuristic checks — included in `nix run .#check` for dev runs but
  # kept out of CI (false positives when an upstream dep ships a major).
  devOnlyChecks = {
    outdated = {
      check = ''
        report="$(cargo outdated --workspace --root-deps-only --format json)"
        breaking_updates="$(
          echo "$report" | jq -r '
            . as $pkg
            | .dependencies[]?
            | select(
                .kind != "Development"
                and .latest != "Removed"
                and .latest != "---"
                and .compat == "---"
              )
            | "\($pkg.crate_name)\t\(.name)\t\(.project)\t\(.latest)"
          '
        )"
        if [ -n "$breaking_updates" ]; then
          echo "Semver-breaking root dependency updates available:"
          printf "crate\tdependency\tcurrent\tlatest\n"
          echo "$breaking_updates"
          exit 1
        fi
        echo "No semver-breaking root dependency updates detected."
      '';
    };
  };

  allChecks = ciChecks // devOnlyChecks;

  # All-runner used by `nix run .#check` / `nix run .#fix`. Carries its
  # own toolchain so it works outside the dev shell.
  mkRunner = mode:
    pkgs.writeShellApplication {
      name = "hellas-${mode}-all";
      runtimeInputs = with pkgs; [
        git
        coreutils
        rustToolchain
        stdenv.cc
        pkg-config
        protobuf
        cargo-sort
        cargo-outdated
        jq
      ];
      text =
        ''
          set -euo pipefail
          cd "$(git rev-parse --show-toplevel)"
        ''
        + lib.concatMapStrings (
          name: let
            c = allChecks.${name};
          in ''

            echo "== ${mode}-${name}"
            ${
              if mode == "check"
              then c.check
              else c.fix
            }
          ''
        ) (
          if mode == "check"
          then lib.attrNames allChecks
          else lib.attrNames (lib.filterAttrs (_: c: c ? fix) allChecks)
        );
    };
in {
  # Flat { name → command } exposed to the CI matrix. Keep this stable;
  # adding a key here adds a CI job (no workflow edit needed).
  commands = lib.mapAttrs (_: c: c.check) ciChecks;
  checkAll = mkRunner "check";
  fixAll = mkRunner "fix";
}
