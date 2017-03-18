
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
    char          email[1024U];
    char          pwd2[1024U];
    char          pwd[1024U];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    size_t        email_len;
    size_t        i;
    int           ret;

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
    crypto_generichash(salt, sizeof salt, (const unsigned char *) email,
                       email_len, NULL, 0);
    sodium_memzero(email, sizeof email);
    ret = crypto_pwhash(k, k_bytes, pwd, strlen(pwd), salt,
                        crypto_pwhash_OPSLIMIT_MODERATE,
                        crypto_pwhash_MEMLIMIT_MODERATE,
                        crypto_pwhash_ALG_DEFAULT);
    sodium_memzero(pwd, sizeof pwd);
    sodium_memzero(salt, sizeof salt);

    safe_write(2, "done\n", sizeof "done\n" - 1U, -1);

    return ret;
}
