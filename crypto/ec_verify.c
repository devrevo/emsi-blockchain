#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hblk_crypto.h"


int ec_verify(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t const *sig) {
  unsigned char cmsg[SHA256_DIGEST_LENGTH];
  
  if(!msg || !key || !sig || !EC_KEY_check_key(key))
    return 0;
  if(!SHA256(msg,msglen,cmsg))
    return 0;
  if(ECDSA_verify(EC_CURVE, cmsg, SHA256_DIGEST_LENGTH, sig->sig, sig->len, (EC_KEY *)key) != 1)
    return 0;
  return 1;
}
