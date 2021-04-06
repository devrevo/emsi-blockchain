#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <llist.h>
#include <openssl/sha.h> 

#define BLOCKCHAIN_DATA_MAX 1024
#define UNUSED(x) (void)(x)


typedef struct blockchain_s
{
  llist_t     *chain;
} blockchain_t;

typedef struct block_info_s
{
  uint32_t    index;
  uint32_t    difficulty;
  uint64_t    timestamp;
  uint64_t    nonce;
  uint8_t     prev_hash[SHA256_DIGEST_LENGTH];

} block_info_t;

typedef struct block_data_s
{
  int8_t      buffer[BLOCKCHAIN_DATA_MAX];
  uint32_t    len;

} block_data_t;

typedef struct block_s
{
  block_info_t    info; 
  block_data_t    data; 
  uint8_t     hash[SHA256_DIGEST_LENGTH];

} block_t;

extern block_t const _genesis;

blockchain_t *blockchain_create(void);

void _blockchain_print(blockchain_t const *blockchain);

void _blockchain_destroy(blockchain_t *blockchain);

block_t *block_create(block_t const *prev, int8_t const *data, uint32_t data_len);

void block_destroy(block_t *block);

void blockchain_destroy(blockchain_t *blockchain);

uint8_t *block_hash(block_t const *block, uint8_t hash_buf[SHA256_DIGEST_LENGTH]);

int blockchain_serialize(blockchain_t const *blockchain, char const *path);

uint8_t _get_endianness(void);

void _swap_endian(void *p, size_t size);

blockchain_t *blockchain_deserialize(char const *path);
