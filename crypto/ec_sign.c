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
if (key == NULL)
return (NULL);
if (msg == NULL)
return (NULL);
if (!EC_KEY_check_key(key))
return (NULL);
bzero(sig->sig, sizeof(sig->sig));
if (ECDSA_sign(EC_CURVE, msg, msglen, sig->sig,
	       &len, (EC_KEY *)key) != 1)
{
sig->len = 0;
return (NULL);
}
sig->len = (uint8_t)len;
return (sig->sig);
}
