# ML-DSA-44 transaction signatures

Status: phase B1 of a proposal (see github.com/Justyoureverydaynormalguybob/koinos-pq,
`docs/NATIVE-PROPOSAL.md`). Devnet and review only; not for mainnet validators until adopted
upstream. No protobuf, state, system-call or genesis change.

## What changes

`transaction.signatures` accepts a second kind of entry next to the 65-byte secp256k1 recoverable
signature:

```
0x01 || public key (1312 bytes) || signature (2420 bytes)      exactly 3733 bytes
```

- The signature is ML-DSA-44 (NIST FIPS 204), pure mode, over the 34-byte transaction id
  multihash, with the fixed context string `koinos/tx/1`.
- The signer address is derived from the public key the way `crypto::public_key::to_address_bytes()`
  derives it from a compressed secp256k1 key: `0x00 || ripemd160( sha256( key ) ) || 4-byte double
  sha256 checksum`. Wallets show it as an ordinary base58 address. koilib computes the same bytes
  with `utils.bitcoinAddress( publicKey )`.
- The default authority check (`check_authority`, `system_calls.cpp`) recognises an entry by its
  exact size and tag byte, verifies it, derives the address and compares it with the account, the
  same way it compares a recovered secp256k1 address. An entry that does not verify authorizes
  nobody and is skipped. Any entry that is neither 65 bytes nor a 3733-byte `0x01` entry fails
  exactly as it did before (`unexpected signature length`).
- 65-byte entries go through the unchanged code path. A transaction may mix both kinds in any
  order.
- `check_system_authority` (genesis key), `recover_public_key`, `verify_signature` and block
  signatures are unchanged in B1.

A post-quantum account is therefore just an address whose key is ML-DSA-44. Moving over means
sending KOIN to such an address and signing from then on with the ML-DSA key.

## Compute charge

The verifier runs natively, outside the metered VM, so the thunk charges explicitly:
`3 x` the `recover_public_key` registry cost (29,630 ticks on mainnet, so 88,890 per entry).
Measured on 2026-10-17 with the vendored reference code: one verification takes 2.6 times a
libsecp256k1 recovery (183 µs against 70 µs, AMD Ryzen 7 7730U, gcc 12 `-O3`); an AVX2 build
takes 0.64 times. The multiplier is a policy number that has to cover the slowest node allowed on
the network; it can come down if an AVX2 build with runtime CPU detection ships. Full benchmark
and the throughput analysis: koinos-pq `docs/THROUGHPUT.md` and `bench/`.

## Verifier

`src/koinos/chain/pq/` is the PQ-Crystals reference implementation of ML-DSA (FIPS 204),
verify-only subset, vendored byte for byte (`pq/PROVENANCE.md`), built as the static library
`koinos_pq` with `DILITHIUM_MODE=2`. `src/koinos/chain/mldsa.cpp` is the only caller.
`pq/randombytes.c` is a trapping stub: key generation and signing never run in the node.

## Tests

`tests/thunk_test.cpp`, case `ml_dsa_44_signatures`:

- all 15 NIST ACVP ML-DSA-44 sigVer vectors agree with the vendored verifier (12 must reject);
- a 3733-byte entry authorizes its address and nobody else;
- a flipped bit in the signature, the key or the transaction id is rejected;
- a signature made with the koinos-pq account contract's context (`koinos/pqwallet/1`) does not
  authorize the native path;
- a wrong tag or a wrong size fails exactly as before;
- 65-byte entries still work and mix with ML-DSA entries in either order;
- the compute charge is three recoveries.

Vectors come from `@noble/post-quantum`, an independent implementation, via
koinos-pq `cli/gen-native-vectors.mjs`, which writes `tests/include/koinos/tests/mldsa_vectors.hpp`.

Build and run with `Dockerfile.test`. Result on 2026-10-17: the whole suite passes, 50 of 50 test
cases and 2,007 of 2,007 assertions.

## Devnet result (2026-10-17)

Private chain from this fork's image (koinos-pq `devnet/`: own genesis key, no block producer,
blocks signed by the genesis key, current KOIN contract flagged as a system contract). Log in
koinos-pq `docs/devnet-run.txt`.

| transaction | result | compute (ticks) | network (bytes) |
|---|---|---|---|
| KOIN transfer, one 3733-byte ML-DSA-44 entry, no secp256k1 anywhere | mined, balance moved | 527,828 | 3,979 |
| KOIN transfer, one 65-byte secp256k1 entry (unchanged path) | mined | 409,273 | 310 |
| two transfers from two accounts, one secp256k1 entry plus one ML-DSA-44 entry | mined | 922,593 | 4,144 |

Difference between the two single transfers: 118,555 ticks and 3,669 bytes. The charge is
two authority checks per transfer (payer, then the token's `require_authority`) at three
recoveries instead of one, 2 x 59,260 = 118,520 ticks, plus 35 ticks of larger-transaction
overhead. Rejected at the mempool, each with the expected error: flipped signature bit, a
signature made with the account contract's context, a valid entry from a different ML-DSA key,
a secp256k1 signature for the post-quantum address, the mixed transaction with only its
secp256k1 signature (all `has not authorized transaction`); tag `0x02` and a 3732-byte entry
(`unexpected signature length`); no signature (`missing expected field`).

## Producing an entry (JavaScript)

```js
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { utils } from "koilib";
const { publicKey, secretKey } = ml_dsa44.keygen(seed32);          // address = utils.bitcoinAddress(publicKey)
const sig = ml_dsa44.sign(txIdBytes34, secretKey, { context: new TextEncoder().encode("koinos/tx/1") });
tx.signatures = [utils.encodeBase64url(Uint8Array.from([0x01, ...publicKey, ...sig]))];
```

## Later (B2)

A `0x02 || signature` entry with the public key stored on chain after first use (2,421 bytes
instead of 3,733), `ml_dsa_44` in the `dsa` enum with a `verify_signature` branch for contracts,
block signatures, and a tag reserved for Falcon-512 (FN-DSA) once FIPS 206 is final.
