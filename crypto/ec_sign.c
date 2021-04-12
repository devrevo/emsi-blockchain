#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hblk_crypto.h"

/**
 * ec_sign - sign a set of bytes, using given private EC_KEY
 * @key: pointer to EC_KEY struct containing private key to perform the signing
 * @msg: pointer to characters to be signed
 * @msglen: len of msg
 * @sig: address to store signature
 *
 * Return: pointer to signature buffer on success, NULL on error
 */
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
	size_t msglen, sig_t *sig)
{
  uint32_t len = 0;

  if (!key || !msg || !msglen)
    return (NULL);

  bzero(sig->sig, sizeof(sig->sig));
  if (!ECDSA_sign(0, msg, msglen, sig->sig, &len, (EC_KEY *)key))
    {
      sig->len = 0;
      return (NULL);
    }

  sig->len = (uint8_t)len;
  return ((uint8_t *)sig->sig);
}
