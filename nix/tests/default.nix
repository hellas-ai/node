{packages, ...}: {
  # Keep checks namespaced under ./nix/tests even when the current check set is small.
  e2e-script = packages."e2e-test";
}
