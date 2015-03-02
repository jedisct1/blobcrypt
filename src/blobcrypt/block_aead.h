
#define block_ABYTES crypto_aead_chacha20poly1305_ABYTES
#define block_KEYBYTES crypto_aead_chacha20poly1305_KEYBYTES
#define block_NONCEBYTES 24U
#define block_MAXBYTES 0x4000000000ULL

static int block_encrypt(unsigned char *c, unsigned long long *clen_p,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *ad, unsigned long long adlen,
                         const unsigned char *message_id,
                         const unsigned char *nonce,
                         const unsigned char *k);

static int block_decrypt(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *c, unsigned long long clen,
                         const unsigned char *ad, unsigned long long adlen,
                         const unsigned char *message_id,
                         const unsigned char *nonce,
                         const unsigned char *k);
