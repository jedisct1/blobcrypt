
#ifndef helpers_H
#define helpers_H

void disable_echo(void);

void enable_echo(void);

ssize_t safe_write(const int fd, const void * const buf_, size_t count,
                   const int timeout);

ssize_t safe_read(const int fd, void * const buf_, size_t count);

ssize_t safe_read_partial(const int fd, void * const buf_, const size_t max_count);

int get_password(char *pwd, size_t max_len, const char *prompt);

#endif
