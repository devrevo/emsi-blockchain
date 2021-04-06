#include <openssl/sha.h>
#include "blockchain.h"


uint8_t *block_hash(block_t const *block, uint8_t hash_buf[SHA256_DIGEST_LENGTH]){
  return (SHA256((const unsigned char *)block->data.buffer,(size_t)block->data.len,hash_buf));
}
