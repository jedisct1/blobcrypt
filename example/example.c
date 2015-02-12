
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "blobcrypt.h"

#define IN_BUFFER_SIZE 1024

static ssize_t
safe_write(const int fd, const void * const buf_, size_t count,
           const int timeout)
{
    struct pollfd  pfd;
    const char    *buf = (const char *) buf_;
    ssize_t        written;

    pfd.fd = fd;
    pfd.events = POLLOUT;

    while (count > (size_t) 0) {
        while ((written = write(fd, buf, count)) <= (ssize_t) 0) {
            if (errno == EAGAIN) {
                if (poll(&pfd, (nfds_t) 1, timeout) == 0) {
                    errno = ETIMEDOUT;
                    goto ret;
                }
            } else if (errno != EINTR) {
                goto ret;
            }
        }
        buf += written;
        count -= (size_t) written;
    }
ret:
    return (ssize_t) (buf - (const char *) buf_);
}

static ssize_t
safe_read(const int fd, void * const buf_, size_t count)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t        readnb;

    assert(count > (size_t) 0U);
    do {
        while ((readnb = read(fd, buf, count)) < (ssize_t) 0 &&
               (errno == EINTR || errno == EAGAIN)); /* LCOV_EXCL_LINE */
        if (readnb < (ssize_t) 0) {
            return readnb; /* LCOV_EXCL_LINE */
        }
        if (readnb == (ssize_t) 0) {
            break; /* LCOV_EXCL_LINE */
        }
        count -= (size_t) readnb;
        buf += readnb;
    } while (count > (ssize_t) 0);

    return (ssize_t) (buf - (unsigned char *) buf_);
}

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

    in = sodium_malloc(IN_BUFFER_SIZE);
    k = sodium_malloc(blobcrypt_KEYBYTES);
    state = sodium_malloc(sizeof *state);
    memset(k, 'K', blobcrypt_KEYBYTES);
    blobcrypt_encrypt_init(state, write_cb, close_success_cb, close_error_cb,
                           NULL, total_len, k);
    while ((readnb = safe_read(fd, in, IN_BUFFER_SIZE)) > 0) {
        blobcrypt_encrypt_update(state, in, (size_t) readnb);
    }
    if (readnb != 0) {
        perror("read");
        return -1;
    }
    if (blobcrypt_encrypt_final(state) == 0) {
        fprintf(stderr, "Success!\n");
    }
    sodium_free(in);
    sodium_free(k);
    sodium_free(state);

    return 0;
}

static int
file_decrypt(int fd)
{    
    unsigned char           *in;
    unsigned char           *k;
    blobcrypt_encrypt_state *state;
    ssize_t                  readnb;

    in = sodium_malloc(IN_BUFFER_SIZE);
    k = sodium_malloc(blobcrypt_KEYBYTES);
    state = sodium_malloc(sizeof *state);
    memset(k, 'K', blobcrypt_KEYBYTES);    
    blobcrypt_decrypt_init(state, write_cb, close_success_cb, close_error_cb,
                           NULL, blobcrypt_UNKNOWNSIZE, k);
    while ((readnb = safe_read(fd, in, IN_BUFFER_SIZE)) > 0) {
        blobcrypt_decrypt_update(state, in, (size_t) readnb);
    }
    if (readnb != 0) {
        perror("read");
        return -1;
    }
    if (blobcrypt_decrypt_final(state) == 0) {
        fprintf(stderr, "Success!\n");
    }
    sodium_free(in);
    sodium_free(k);
    sodium_free(state);

    return 0;
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
