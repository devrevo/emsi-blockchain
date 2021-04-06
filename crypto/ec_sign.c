#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hblk_crypto.h"


uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t *sig){

  unsigned char cmsg[SHA256_DIGEST_LENGTH];
  if(!key || !msg || !EC_KEY_check_key(key)){
    return NULL;
  }
  if(!SHA256(msg,msglen,cmsg)){
    return NULL;
  }
  sig->len = ECDSA_size(key);
  if(!sig->len || sig->len > SIG_MAX_LEN)
    return NULL;
  if(!ECDSA_sign(EC_CURVE, cmsg, SHA256_DIGEST_LENGTH, sig->sig, (unsigned int *)&sig->len, (EC_KEY *)key)){
    return NULL;
  }
  return sig->sig;
}
