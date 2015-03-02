
#ifndef _POSIX_SOURCE
# define _POSIX_SOURCE 1
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#ifndef SSIZE_MAX
# define SSIZE_MAX (SIZE_MAX / 2U - 1U)
#endif

#include "blobcrypt.h"
