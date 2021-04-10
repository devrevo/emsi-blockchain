#include "blockchain.h"
/**
 * blockchain_destroy - deletes the blockchain
 * @blockchain: blockchain to be deleted
 */
void blockchain_destroy(blockchain_t *blockchain){
if (!blockchain)
return;
if (llist_destroy(blockchain->chain, 0, NULL) == 0)
free(blockchain);
}
