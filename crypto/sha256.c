#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hblk_crypto.h"

/* Giving a body to *sha256
 * This function computes the hash of a sequence s and stores it into digest
 * return a pointer to digest if digest is null do nothing and return null.
 */
uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH])
{
  if(s == NULL){
    return NULL;
  }else{
    int8_t i;
    for(i=0;i<(int8_t)len;i++){
      digest[i] = (uint8_t)s[i];
    }
    return digest;
  }
}
