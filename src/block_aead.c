
#define NONCE_EXTENSION_BYTES (block_NONCEBYTES - \
                               crypto_aead_chacha20poly1305_NPUBBYTES)

static const unsigned char personal[crypto_generichash_blake2b_PERSONALBYTES] =
{ 0x42, 0x6c, 0x6f, 0x62, 0x43, 0x72, 0x79, 0x70,
  0x74, 0x5f, 0x4c, 0x69, 0x62, 0x2d, 0x01, 0x00 };

static int
block_encrypt(unsigned char *c, unsigned long long *clen_p,
              const unsigned char *m, unsigned long long mlen,
              const unsigned char *ad, unsigned long long adlen,
              const unsigned char *salt, const unsigned char *nonce,
              const unsigned char *k)
{
    unsigned char subkey[crypto_aead_chacha20poly1305_KEYBYTES];
    int           ret;

    if (crypto_generichash_blake2b_salt_personal(subkey, sizeof subkey,
                                                 nonce, NONCE_EXTENSION_BYTES,
                                                 k,
                                                 crypto_aead_chacha20poly1305_KEYBYTES,
                                                 salt, personal) != 0) {
        return -1;
    }
    ret = crypto_aead_chacha20poly1305_encrypt(c, clen_p, m, mlen, ad, adlen,
                                               NULL,
                                               nonce + NONCE_EXTENSION_BYTES,
                                               subkey);
    sodium_memzero(subkey, sizeof subkey);

    return ret;
}

static int
block_decrypt(unsigned char *m, unsigned long long *mlen_p,
              const unsigned char *c, unsigned long long clen,
              const unsigned char *ad, unsigned long long adlen,
              const unsigned char *salt,  const unsigned char *nonce,
              const unsigned char *k)
{
    unsigned char subkey[crypto_aead_chacha20poly1305_KEYBYTES];
    int           ret;

    if (crypto_generichash_blake2b_salt_personal(subkey, sizeof subkey,
                                                 nonce, NONCE_EXTENSION_BYTES,
                                                 k,
                                                 crypto_aead_chacha20poly1305_KEYBYTES,
                                                 salt, personal) != 0) {
        return -1;
    }
    ret = crypto_aead_chacha20poly1305_decrypt(m, mlen_p, NULL, c, clen, ad,
                                               adlen,
                                               nonce + NONCE_EXTENSION_BYTES,
                                               subkey);
    sodium_memzero(subkey, sizeof subkey);

    return ret;
}
