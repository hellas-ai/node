{
  pkgs,
  lib,
  rustToolchain,
}: let
  mkCICheck = {
    name,
    cmd,
    inputs ? [],
  }:
    pkgs.writeShellApplication {
      name = "hellas-${name}";
      runtimeInputs = [pkgs.git pkgs.coreutils] ++ inputs;
      text = ''
        set -euo pipefail
        repo_root="$(git rev-parse --show-toplevel)"
        cd "$repo_root"
        ${cmd}
      '';
    };

  mkCIChecks = write:
    with lib; let
      mode =
        if write
        then "fix"
        else "check";
      checks = {
        sort = {
          inputs = [pkgs.cargo-sort];
          cmd = ''
            cargo-sort --workspace ${optionalString (!write) "--check"}
          '';
        };

        fmt = {
          inputs = [rustToolchain];
          cmd = ''
            cargo fmt --all ${optionalString (!write) "-- --check"}
          '';
        };

        clippy = {
          inputs = [rustToolchain];
          cmd = ''
            cargo clippy ${optionalString write "--fix --allow-dirty --allow-staged"} --workspace --all-targets -- -D warnings
          '';
        };

        outdated = {
          inputs = [rustToolchain pkgs.cargo-outdated pkgs.jq];
          cmd = ''
            report="$(
              cargo outdated --workspace --root-deps-only --format json
            )"
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
      base = mapAttrs (name: cfg:
        mkCICheck {
          name = "${mode}-${name}";
          cmd = cfg.cmd;
          inputs = cfg.inputs or [];
        })
      checks;
    in
      base
      // {
        all = mkCICheck {
          name = "${mode}-all";
          inputs = [rustToolchain];
          cmd = ''
            ${base.sort}/bin/hellas-${mode}-sort
            ${base.fmt}/bin/hellas-${mode}-fmt
            ${base.clippy}/bin/hellas-${mode}-clippy
            ${base.outdated}/bin/hellas-${mode}-outdated
          '';
        };
      };
in {
  checkPackages = mkCIChecks false;
  fixPackages = mkCIChecks true;
}
