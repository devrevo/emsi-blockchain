#include "blockchain.h"
/**
 * blockchain_destroy - deletes the blockchain
 * @blockchain: blockchain to be deleted
 */
void blockchain_destroy(blockchain_t *blockchain){
if (!blockchain)
return;
if (llist_destroy(blockchain->chain, 1, (node_dtor_t)free) == 0)
free(blockchain);
}
