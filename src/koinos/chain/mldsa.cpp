#include <koinos/chain/mldsa.hpp>

#include <array>
#include <cstring>

#include <koinos/crypto/multihash.hpp>
#include <koinos/util/conversion.hpp>

extern "C"
{
// Vendored PQ-Crystals reference implementation, built with DILITHIUM_MODE=2 (ML-DSA-44).
// Declared here rather than by including the vendored headers so their short macro names
// (N, Q, K, L, ...) do not leak into the chain's namespace.
int pqcrystals_dilithium2_ref_verify( const uint8_t* sig,
                                      size_t siglen,
                                      const uint8_t* m,
                                      size_t mlen,
                                      const uint8_t* ctx,
                                      size_t ctxlen,
                                      const uint8_t* pk );
}

namespace koinos::chain::mldsa {

bool verify( std::string_view signature,
             std::string_view message,
             std::string_view context,
             std::string_view public_key )
{
  if( signature.size() != signature_size || public_key.size() != public_key_size || context.size() > 255 )
    return false;

  return pqcrystals_dilithium2_ref_verify( reinterpret_cast< const uint8_t* >( signature.data() ),
                                           signature.size(),
                                           reinterpret_cast< const uint8_t* >( message.data() ),
                                           message.size(),
                                           reinterpret_cast< const uint8_t* >( context.data() ),
                                           context.size(),
                                           reinterpret_cast< const uint8_t* >( public_key.data() ) )
         == 0;
}

std::string address_bytes( std::string_view public_key, std::byte prefix )
{
  // Mirrors public_key_impl::to_address_bytes() in koinos-crypto-cpp (src/koinos/crypto/elliptic.cpp).
  auto sha256    = crypto::hash( crypto::multicodec::sha2_256, public_key.data(), public_key.size() );
  auto ripemd160 = crypto::hash( crypto::multicodec::ripemd_160, sha256 );

  std::array< std::byte, 25 > d;
  d[ 0 ] = prefix;
  std::memcpy( d.data() + 1, ripemd160.digest().data(), ripemd160.digest().size() );
  sha256 = crypto::hash( crypto::multicodec::sha2_256, (char*)d.data(), ripemd160.digest().size() + 1 );
  sha256 = crypto::hash( crypto::multicodec::sha2_256, sha256 );
  std::memcpy( d.data() + ripemd160.digest().size() + 1, sha256.digest().data(), 4 );

  return util::converter::as< std::string >( d );
}

} // namespace koinos::chain::mldsa
