#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace koinos::chain::mldsa {

/*
 * ML-DSA-44 (NIST FIPS 204) transaction signatures.
 *
 * A transaction signature entry of exactly `entry_size` bytes whose first byte is `entry_tag` is an
 * ML-DSA-44 entry:
 *
 *   0x01 || public key (1312 bytes) || signature (2420 bytes)
 *
 * The signature is over the transaction id (the 34 byte multihash, as for secp256k1) in FIPS 204
 * pure mode with the fixed context string `transaction_context`. The signer's address is derived
 * from the public key exactly as it is for secp256k1 keys: 0x00 || ripemd160( sha256( key ) ) ||
 * 4 byte double sha256 checksum. 65 byte entries are unchanged.
 */

constexpr std::size_t public_key_size = 1'312;
constexpr std::size_t signature_size  = 2'420;
constexpr std::size_t entry_size      = 1 + public_key_size + signature_size; // 3733
constexpr std::uint8_t entry_tag      = 0x01;

// FIPS 204 context. Distinct from the koinos-pq account contract's "koinos/pqwallet/1" so a
// signature made for one can never be replayed as the other.
constexpr std::string_view transaction_context = "koinos/tx/1";

// Compute charged for one verification, in units of the `recover_public_key` thunk's registry cost.
// Measured 2026-10-17: the reference verifier takes 2.6x a secp256k1 recovery (183 us against 70 us,
// AMD Ryzen 7 7730U). See docs/ml-dsa-44-signatures.md.
constexpr std::uint64_t verify_cost_in_recoveries = 3;

// True if `signature` is a valid ML-DSA-44 signature by `public_key` over `message` with `context`.
// Wrong sizes return false; this never throws.
bool verify( std::string_view signature,
             std::string_view message,
             std::string_view context,
             std::string_view public_key );

// Address bytes for an arbitrary public key byte string, computed the same way
// crypto::public_key::to_address_bytes() computes them for a compressed secp256k1 key.
std::string address_bytes( std::string_view public_key, std::byte prefix = std::byte{ 0x00 } );

// True if `entry` has the ML-DSA-44 entry shape (size and tag). Does not verify anything.
inline bool is_entry( std::string_view entry )
{
  return entry.size() == entry_size && static_cast< std::uint8_t >( entry[ 0 ] ) == entry_tag;
}

} // namespace koinos::chain::mldsa
