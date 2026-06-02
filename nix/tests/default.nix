{
  self,
  pkgs,
  lib,
  package,
}:
(import ./basic.nix { inherit pkgs package; })
// (import ./e2e.nix {
  inherit
    self
    pkgs
    lib
    package
    ;
})
