
#ifndef blobcrypt_H
#define blobcrypt_H

#include <stddef.h>

#define blobcrypt_BLOCKSIZE 65536U
#define blobcrypt_KEYBYTES 32U
#define blobcrypt_UNKNOWNSIZE 0xffffffffffffffffULL

typedef struct blobcrypt_state {
    unsigned char          k[blobcrypt_KEYBYTES];
    unsigned char          message_id[32U];
    int (*write_cb)        (void *user_ptr, unsigned char *buf, size_t len);
    int (*close_success_cb)(void *user_ptr);
    int (*close_error_cb)  (void *user_ptr);
    void                  *user_ptr;
    unsigned long long     total_len;
    unsigned long long     offset;
    size_t                 buf_pos;
    size_t                 block_size;
    int                    state;
    /* ---------------------------- */
    unsigned char          nonce[24U];
    unsigned char          buf[blobcrypt_BLOCKSIZE];
    unsigned char          auth[16U];
} blobcrypt_state;

typedef blobcrypt_state blobcrypt_encrypt_state;
typedef blobcrypt_state blobcrypt_decrypt_state;

int blobcrypt_encrypt_init(blobcrypt_encrypt_state *state,
                           int (*write_cb)(void *user_ptr,
                                           unsigned char *buf, size_t len),
                           int (*close_success_cb)(void *user_ptr),
                           int (*close_error_cb)(void *user_ptr),
                           void *user_ptr, unsigned long long total_len,
                           const unsigned char *k);

int blobcrypt_encrypt_update(blobcrypt_encrypt_state *state,
                             const unsigned char *in,
                             unsigned long long len);

int blobcrypt_encrypt_final(blobcrypt_encrypt_state *state);

int blobcrypt_decrypt_init(blobcrypt_decrypt_state *state,
                           int (*write_cb)(void *user_ptr,
                                           unsigned char *buf, size_t len),
                           int (*close_success_cb)(void *user_ptr),
                           int (*close_error_cb)(void *user_ptr),
                           void *user_ptr, unsigned long long total_len,
                           const unsigned char *k);

int blobcrypt_decrypt_update(blobcrypt_decrypt_state *state,
                             const unsigned char *in,
                             unsigned long long len);

int blobcrypt_decrypt_final(blobcrypt_decrypt_state *state);

#endif
