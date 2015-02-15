
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "blobcrypt.h"
#include "helpers.h"

#define IN_BUFFER_SIZE 1024

static int
write_cb(void *user_ptr, unsigned char *buf, size_t len)
{
    (void) user_ptr;
    (void) safe_write(1, buf, len, -1);

    return 0;
}

static int
close_success_cb(void *user_ptr)
{
    (void) user_ptr;
    fprintf(stderr, "Closing descriptor [SUCCESS]\n");

    return 0;
}

static int
close_error_cb(void *user_ptr)
{
    (void) user_ptr;
    fprintf(stderr, "Closing descriptor [FAILURE]\n");

    return 0;
}

static int
get_key_from_password(unsigned char *k, size_t k_bytes, int confirm)
{
    static const unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES] =
    { 'A', ' ', 'f', 'i', 'x', 'e', 'd', ' ', 's', 'a', 'l', 't', ' ',
      'f', 'o', 'r', ' ', 't', 'h', 'i', 's', ' ',
      'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', '.', '.' };
    char           h0[56];
    char           pwd[1024U];
    char           pwd2[1024U];

    if (get_password(pwd, sizeof pwd, "Password: ") != 0) {
        return -1;
    }
    if (confirm != 0) {
        if (get_password(pwd2, sizeof pwd2, "Password (one more time): ") != 0) {
            sodium_memzero(pwd, sizeof pwd);
            sodium_memzero(pwd2, sizeof pwd2);
            return -1;
        }
        if (strcmp(pwd, pwd2) != 0) {
            sodium_memzero(pwd, sizeof pwd);
            sodium_memzero(pwd2, sizeof pwd2);
            safe_write(2, "Passwords don't match\n",
                       sizeof "Passwords don't match\n" - 1U, -1);
            return -1;
        }
        sodium_memzero(pwd2, sizeof pwd2);
    }
    crypto_generichash((unsigned char *) h0, sizeof h0,
                       (const unsigned char *) pwd,
                       strlen(pwd), NULL, 0);
    sodium_memzero(pwd, sizeof pwd);

    return crypto_pwhash_scryptsalsa208sha256
        (k, k_bytes, h0, sizeof h0, salt,
         crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
         crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
}

static int
file_encrypt(int fd, off_t total_len)
{

    unsigned char           *in;
    unsigned char           *k;
    blobcrypt_encrypt_state *state;
    ssize_t                  readnb;
    int                      ret = -1;

    k = sodium_malloc(blobcrypt_KEYBYTES);
    if (get_key_from_password(k, blobcrypt_KEYBYTES, 1) != 0) {
        sodium_free(k);
        return -1;
    }
    in = sodium_malloc(IN_BUFFER_SIZE);
    state = sodium_malloc(sizeof *state);
    blobcrypt_encrypt_init(state, write_cb, close_success_cb, close_error_cb,
                           NULL, total_len, k);
    do {
        if ((readnb = safe_read(fd, in, IN_BUFFER_SIZE)) <= 0) {
            if (readnb == -1) {
                perror("read");
            }
            break;
        }
    } while (blobcrypt_encrypt_update(state, in, (size_t) readnb) == 0);
    if (blobcrypt_encrypt_final(state) == 0) {
        fprintf(stderr, "Success!\n");
        ret = 0;
    }
    sodium_free(in);
    sodium_free(k);
    sodium_free(state);

    return ret;
}

static int
file_decrypt(int fd)
{
    unsigned char           *in;
    unsigned char           *k;
    blobcrypt_encrypt_state *state;
    ssize_t                  readnb;
    int                      ret = -1;

    k = sodium_malloc(blobcrypt_KEYBYTES);
    if (get_key_from_password(k, blobcrypt_KEYBYTES, 0) != 0) {
        sodium_free(k);
        return -1;
    }
    in = sodium_malloc(IN_BUFFER_SIZE);
    state = sodium_malloc(sizeof *state);
    blobcrypt_decrypt_init(state, write_cb, close_success_cb, close_error_cb,
                           NULL, blobcrypt_UNKNOWNSIZE, k);
    do {
        if ((readnb = safe_read(fd, in, IN_BUFFER_SIZE)) <= 0) {
            if (readnb == -1) {
                perror("read");
            }
            break;
        }
    } while (blobcrypt_decrypt_update(state, in, (size_t) readnb) == 0);
    if (blobcrypt_decrypt_final(state) == 0) {
        fprintf(stderr, "Success!\n");
        ret = 0;
    }
    sodium_free(in);
    sodium_free(k);
    sodium_free(state);

    return ret;
}

static void
usage(void)
{
    printf("Usage: blobcrypt -d|-e <file>\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    struct stat st;
    int         fd;
    int         ret = -1;

    if (argc != 3) {
        usage();
    }
    if ((fd = open(argv[2], O_RDONLY)) == -1) {
        perror("open");
        return 1;
    }
    if (fstat(fd, &st) != 0) {
        perror("fdstat");
        (void) close(fd);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[%s] is not a regular file\n", argv[2]);
        (void) close(fd);
        return 1;
    }
    sodium_init();
    if (strcmp(argv[1], "-e") == 0) {
        ret = file_encrypt(fd, st.st_size);
    } else if (strcmp(argv[1], "-d") == 0) {
        ret = file_decrypt(fd);
    } else {
        usage();
    }
    close(fd);

    return -ret;
}
