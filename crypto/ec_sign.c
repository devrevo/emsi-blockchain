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
unsigned char cmsg[SHA256_DIGEST_LENGTH];
if (!key || !msg || !sig)
return (NULL);
if (!SHA256(msg, msglen, cmsg))
return (NULL);
sig->len = ECDSA_size(key) + 1;
if (!sig->len || sig->len > SIG_MAX_LEN)
return (NULL);
if (ECDSA_sign(EC_CURVE, msg, SHA256_DIGEST_LENGTH, sig->sig,
	       (unsigned int *)&sig->len, (EC_KEY *)key) != 1)
return (NULL);
return (sig->sig);
}

