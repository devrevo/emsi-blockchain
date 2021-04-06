

#include "blockchain.h"

void blockchain_destroy(blockchain_t *blockchain){
  if(llist_destroy(blockchain->chain, 1, (node_dtor_t)free) == 0){
    printf("Done");
  }
  free(blockchain);
}
