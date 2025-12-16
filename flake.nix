{
  description = "Hellas Node";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rust-toolchain = pkgs.buildPackages.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatform = pkgs.makeRustPlatform {
        rustc = rust-toolchain;
        cargo = rust-toolchain;
      };

      commonArgs = {
        pname = "hellas";
        version = "0.1.0";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "catgrad-0.2.1" = "sha256-rlhwlUACdJyIlRg2jTA5nb2KcPQ+lCpWnhu68Z2idbM=";
          };
        };
        auditable = false;
        defaultFeatures = false;
        buildInputs = with pkgs; [openssl];
        nativeBuildInputs = with pkgs; [pkg-config protobuf];
        checkInputs = with pkgs; [cargo-deny cargo-outdated];
        separateDebugInfo = true;
        meta.mainProgram = "hellas-cli";
      };

      cli = rustPlatform.buildRustPackage commonArgs;
      server = rustPlatform.buildRustPackage (commonArgs // {buildFeatures = ["serve"];});
    in {
      packages = {
        default = cli;
        inherit cli server;
      };

      overlays.default = final: _prev: {
        hellas = self.packages.${final.system}.cli;
        hellas-serve = self.packages.${final.system}.server;
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [self.packages.${system}.default];
        buildInputs = with pkgs; [
          pre-commit
          protobuf-language-server
          cargo-watch
          gh
        ];
      };
    })
    // {
      nixosModules.hellas = {
        config,
        lib,
        pkgs,
        ...
      }: let
        inherit (lib) mkEnableOption mkIf mkOption types concatStringsSep optional;
        cfg = config.services.hellas;
        cliArgs = concatStringsSep " " (["serve"] ++ optional cfg.discovery "--discovery" ++ cfg.extraArgs);
      in {
        options.services.hellas = {
          enable = mkEnableOption "Hellas node server";
          package = mkOption {
            type = types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
            description = "Package providing the hellas CLI (with serve feature).";
          };
          discovery = mkOption {
            type = types.bool;
            default = false;
            description = "Enable discovery (LAN mDNS + internet discovery via pkarr/DNS + DHT).";
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = "Open firewall port for the hellas node.";
          };
          port = mkOption {
            type = types.port;
            default = 31145;
            description = "Port for the hellas node to listen on.";
          };
          extraArgs = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Extra arguments to pass to `hellas-cli serve`.";
          };
        };

        config = mkIf cfg.enable {
          systemd.services.hellas = {
            description = "Hellas node server";
            wantedBy = ["multi-user.target"];
            after = ["network-online.target"];
            wants = ["network-online.target"];
            environment = {
              HOME = "/var/lib/hellas";
            };
            serviceConfig = {
              ExecStart = "${cfg.package}/bin/hellas-cli ${cliArgs}";
              Restart = "on-failure";
              DynamicUser = true;
              StateDirectory = "hellas";
              WorkingDirectory = "/var/lib/hellas";
            };
          };

          networking.firewall = mkIf cfg.openFirewall {
            allowedUDPPorts = [cfg.port];
          };
        };
      };

      nixosModules.default = self.nixosModules.hellas;
    };
}
