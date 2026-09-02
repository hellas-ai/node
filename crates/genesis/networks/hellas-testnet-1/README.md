# `hellas-testnet-1`

The second network whose genesis document ships inside the binary,
selectable as `--network testnet`.

It is **not** a released network and must not hold anything of value.

## Its credentials are public, on purpose

The six validator identities are reproducible with validator seed `200`,
and the two funded P-256 accounts are reproducible from the secret
scalars below. Anyone can therefore sign as any of them.

| account | settlement key | secret scalar |
| --- | --- | --- |
| maker | `hqgPbXjUNxf79VX9sae1ZCFkEhVnorZruoL7Xb96QDwR` | `0000000000000000000000000000000000000000000000000000000000000003` |
| taker | `rh7YVS6csrzr7uQ6vvoy6xXnCm5YmQmAe7R3ym1HQFN1` | `0000000000000000000000000000000000000000000000000000000000000004` |

This is the same arrangement `hellas-devnet-1` uses and carries the same
warning: these credentials are intentionally public and unsafe for any
value-bearing deployment. A network whose committee only the operator
can sign for needs private key material that does not belong in a
repository — that is a different document, generated with
`validator generate-network`, and this is not it.

## What differs from `hellas-devnet-1`

Everything that could otherwise let one network's material work on the
other:

- a different validator seed (`200`, not `100`), so the two committees
  are disjoint;
- different funded scalars (`3`/`4`, not `1`/`2`), so a devnet key is
  not automatically funded here.

The signature domains are already separated — every authorization
commits to its `NetworkId`, so a devnet-signed transaction is invalid
here regardless — but a document that reused the same accounts would
make the two networks needlessly easy to confuse in a terminal.

## Reproducing it

```
hellas-cli chain validator config -n 6 -i 0 --seed 200 \
    --genesis crates/genesis/networks/hellas-testnet-1/genesis.json
```

The `--genesis` check refuses unless the identities `--seed 200`
generates match the ones committed here, so that command is also the
test that this document is what it claims to be.
