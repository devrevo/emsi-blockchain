
#include "blockchain.h"

blockchain_t *blockchain_create(void){
  block_t const _genesis =  {
    { /* info */
      0 /* index */,
      0, /* difficulty */
      1537578000, /* timestamp */
      0, /* nonce */
      {0} /* prev_hash */
    },
    { /* data */
      "Holberton School", /* buffer */
      16 /* len */
    },
    "\xc5\x2c\x26\xc8\xb5\x46\x16\x39\x63\x5d\x8e\xdf\x2a\x97\xd4\x8d"
    "\x0c\x8e\x00\x09\xc8\x17\xf2\xb1\xd3\xd7\xff\x2f\x04\x51\x58\x03"
    /* hash */
    /* c52c26c8b5461639635d8edf2a97d48d0c8e0009c817f2b1d3d7ff2f04515803 */
  };
  blockchain_t *blockchain;
  block_t * ptr;
  ptr = (block_t *) malloc(sizeof(block_t));
  
  memcpy(ptr,(block_t *) &_genesis, sizeof(block_t));

  blockchain = (blockchain_t *) malloc(sizeof(blockchain_t));
  blockchain->chain = llist_create(MT_SUPPORT_TRUE);
  
  if(llist_add_node(blockchain->chain, ptr, ADD_NODE_FRONT) != 0){
    return NULL;
  }
 
  return blockchain;
}
