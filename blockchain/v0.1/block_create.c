#include "blockchain.h"
#include <time.h>
/**
 * block_create - creates a new block
 * @prev: previous block
 * @data: data for a new block
 * @data_len: length of @data
 * Return: a block or NULL if failed
 */
block_t *block_create(block_t const *prev,
		      int8_t const *data, uint32_t data_len)
{
block_t *block;
block_info_t *block_info;
block_data_t *block_data;
time_t t;
int i;
uint8_t *hash;
block = (block_t *)malloc(sizeof(block_t));
block_data = (block_data_t *)malloc(sizeof(block_data_t));
block_info = (block_info_t *)malloc(sizeof(block_info_t));
hash = (uint8_t *)malloc(sizeof(uint8_t) * SHA256_DIGEST_LENGTH);
block_info->index = (uint32_t)((int)(prev->info.index) + 1);
block_info->difficulty = 0;
t = time(0);
block_info->timestamp = (uint64_t)&t;
block_info->nonce = 0;
memcpy(block_info->prev_hash, prev->hash, sizeof(prev->hash));
if (data_len >= (uint32_t)BLOCKCHAIN_DATA_MAX)
{
for (i = 0; i < BLOCKCHAIN_DATA_MAX; i++)
block_data->buffer[i] = data[i];
block_data->len = BLOCKCHAIN_DATA_MAX;
}
if (data_len < (uint32_t)BLOCKCHAIN_DATA_MAX)
{
for (i = 0; i < (int)data_len; i++)
block_data->buffer[i] = data[i];
block_data->len = data_len;
}
for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
hash[i] = 0;
memcpy(&block->data, ((block_data_t *)block_data), sizeof(block_data_t));
memcpy(&block->info, ((block_info_t *)block_info), sizeof(block_info_t));
memcpy(&block->hash, ((uint8_t *)hash), sizeof(uint8_t));
free(block_data);
free(block_info);
free(hash);
return (block);
}
