{
  pkgs,
  rustToolchain,
  cli,
}:
let
  imageRepository = "ghcr.io/hellas-ai/hellas";

  runtime =
    pkgs.runCommand "hellas-cli-network-runtime"
      {
        nativeBuildInputs = [ pkgs.removeReferencesTo ];
      }
      ''
        mkdir -p "$out/bin"
        cp "${cli}/bin/hellas-cli" "$out/bin/hellas-cli"
        chmod u+w "$out/bin/hellas-cli"
        remove-references-to -t ${rustToolchain} "$out/bin/hellas-cli"
        chmod 0555 "$out/bin/hellas-cli"
      '';

  image = pkgs.dockerTools.streamLayeredImage {
    name = imageRepository;
    tag = "network";
    contents = [
      runtime
      pkgs.cacert
      pkgs.iana-etc
      pkgs.stdenv.cc.cc.lib
      pkgs.glibc
    ];
    config = {
      Entrypoint = [
        "${runtime}/bin/hellas-cli"
        "serve"
      ];
      WorkingDir = "/var/lib/hellas";
      Volumes."/var/lib/hellas" = { };
      ExposedPorts."31145/udp" = { };
      Env = [
        "HOME=/var/lib/hellas"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      ];
    };
  };

  push = pkgs.writeShellApplication {
    name = "docker-push";
    runtimeInputs = [ pkgs.skopeo ];
    text = ''
      ${image} | skopeo copy docker-archive:/dev/stdin "docker://${imageRepository}:network" "$@"
    '';
  };
in
{
  inherit image push;
}
