#include <openssl/sha.h>
#include "blockchain.h"

/**
 * block_hash - get the hash of a block
 * @block: block to be hashed, only hash field will not be hashed
 * @hash_buf: buffer for digest
 * Return: hash digest or NULL if failed
 */
uint8_t *block_hash(block_t const *block,
		    uint8_t hash_buf[SHA256_DIGEST_LENGTH])
{
if (block == NULL)
return (NULL);
if (!SHA256((const unsigned char *)block->data.buffer,(size_t)block->data.len, hash_buf))
return (NULL);
return (hash_buf);
}
