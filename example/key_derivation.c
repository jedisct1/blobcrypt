
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <sodium.h>
#include <string.h>

#include "helpers.h"
#include "key_derivation.h"

int
get_key_from_password(unsigned char *k, size_t k_bytes, int confirm)
{
#define SALT_PREFIX "Personalization for this example"
#define SALT_PREFIX_LEN 32

    char          email[1024U];
    char          pwd2[1024U];
    char          pwd[1024U];
    unsigned char salt[SALT_PREFIX_LEN + 1024U];
    unsigned char h0[56];
    size_t        email_len;
    size_t        i;
    int           ret;

    assert(strlen(SALT_PREFIX) == SALT_PREFIX_LEN);
    if (get_line(email, sizeof email, "Email: ") != 0) {
        return -1;
    }
    email_len = strlen(email);
    for (i = 0U; i < email_len; i++) {
        email[i] = (char) tolower((unsigned char) email[i]);
    }
    if (get_password(pwd, sizeof pwd, "Password: ") != 0) {
        return -1;
    }
    if (*pwd == 0) {
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
    safe_write(2, "Deriving key from password... ",
               sizeof "Deriving key from password... " - 1U, -1);
    crypto_generichash(h0, sizeof h0, (const unsigned char *) pwd,
                       strlen(pwd), NULL, 0);
    sodium_memzero(pwd, sizeof pwd);
    memcpy(salt + SALT_PREFIX_LEN, email, email_len);
    sodium_memzero(email, sizeof email);
    ret = crypto_pwhash_scryptsalsa208sha256_ll(h0, sizeof h0, salt,
                                                SALT_PREFIX_LEN + email_len,
                                                1ULL << 18, 1U, 8U, k, k_bytes);
    sodium_memzero(h0, sizeof h0);
    sodium_memzero(salt, sizeof salt);

    safe_write(2, "done\n", sizeof "done\n" - 1U, -1);

    return ret;
}
