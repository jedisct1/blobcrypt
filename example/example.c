
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
#include "key_derivation.h"

#define IN_BUFFER_SIZE 65536

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
file_encrypt(int fd, off_t total_len)
{

    unsigned char           *in;
    unsigned char           *k;
    blobcrypt_encrypt_state *state;
    ssize_t                  readnb;
    int                      ret = -1;

    if (isatty(1)) {
        fprintf(stderr, "I'm not going to write to a terminal\n");
        return -1;
    }
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
    if (sodium_init() != 0) {
        return 1;
    }
    if (strcmp(argv[1], "-e") == 0) {
        ret = file_encrypt(fd, st.st_size);
    } else if (strcmp(argv[1], "-d") == 0) {
        ret = file_decrypt(fd);
    } else {
        usage();
    }
    close(fd);

    if (ret != 0) {
        fprintf(stderr, "Aborted.\n");
    }

    return -ret;
}
