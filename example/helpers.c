
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "helpers.h"

#ifndef TCSAFLUSH
# define TCSAFLUSH 0
#endif

void
disable_echo(void)
{
    struct termios p;

    if (!isatty(0) || tcgetattr(0, &p) != 0) {
        return;
    }
    p.c_lflag &= ~ECHO;
    tcsetattr(0, TCSAFLUSH, &p);
}

void
enable_echo(void)
{
    struct termios p;

    if (!isatty(0) || tcgetattr(0, &p) != 0) {
        return;
    }
    p.c_lflag |= ECHO;
    tcsetattr(0, TCSAFLUSH, &p);
}

ssize_t
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

ssize_t
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

ssize_t
safe_read_partial(const int fd, void * const buf_, const size_t max_count)
{
    unsigned char * const buf = (unsigned char *) buf_;
    ssize_t               readnb;

    while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 &&
           errno == EINTR);

    return readnb;
}

int
get_line(char *line, size_t max_len, const char *prompt)
{
    char   *line_lf;
    ssize_t readnb;
    size_t  line_pos = 0U;
    int     ret = -1;

    memset(line, 0, max_len);
    if (max_len < 2U) {
        return -1;
    }
    if (isatty(2)) {
        safe_write(2, prompt, strlen(prompt), -1);
    }
    for (;;) {
        readnb = safe_read_partial(0, line + line_pos, max_len - 1U - line_pos);
        if (readnb < 0 || readnb >= (ssize_t) (max_len - line_pos)) {
            ret = -1;
            break;
        }
        line_pos += readnb;
        if ((line_lf = strchr(line, '\n')) != NULL) {
            *line_lf = 0;
            ret = 0;
            break;
        }
        if (readnb == 0) {
            ret = 0;
            break;
        }
    }
    line[line_pos] = 0;
    if (isatty(2)) {
        if (line_pos >= max_len - 1U) {
            safe_write(2, "(truncated)", sizeof "(truncated)" - 1U, -1);
        }
        safe_write(2, "\n", 1U, -1);
    }
    return ret;
}

int
get_password(char *pwd, size_t max_len, const char *prompt)
{
    int ret;

    disable_echo();
    ret = get_line(pwd, max_len, prompt);
    enable_echo();

    return ret;
}
