# `hellas-mainnet-1`

This directory is the canonical public configuration for the first Hellas
production network.

- Validator identities are ordered by genesis and use the stable deployment
  labels `fsn1`, `nbg1`, `hel`, `ash`, `hil`, and `sin`.
- Validator private configurations were generated with cryptographic
  randomness by `hellas chain validator generate-network`.
- Private validator configurations live only in host-specific SOPS files in
  the infrastructure repository and are loaded through systemd credentials.
- The sole genesis allocation belongs to the SOPS-encrypted mainnet treasury
  key. There is no recovery mechanism outside that encrypted key material.

Changing this document creates a different network. Do not edit it after
launch.
