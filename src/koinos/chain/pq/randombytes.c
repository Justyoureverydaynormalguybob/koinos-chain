/* Not part of the upstream reference code.
 *
 * The node only ever verifies ML-DSA-44 signatures. Key generation and signing live in wallets.
 * sign.c still references randombytes() from those code paths, so the symbol must exist to link,
 * but nothing in koinos_chain may reach it. If it is ever called the process aborts rather than
 * returning weak randomness. */
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include "randombytes.h"

void randombytes( uint8_t* out, size_t outlen )
{
  (void)out;
  (void)outlen;
  abort();
}
