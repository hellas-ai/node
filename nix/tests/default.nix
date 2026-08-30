{
  self,
  pkgs,
  lib,
  package,
  networkPackage,
  validatorPackage,
}:
(import ./basic.nix {
  inherit pkgs package networkPackage;
})
// (import ./e2e.nix {
  inherit
    self
    pkgs
    lib
    package
    validatorPackage
    ;
})
