
Blobcrypt
=========

Blobcrypt is a small library to encrypt and decrypt large files and
data streams using libsodium.

Installation
============

The only prerequisite is [libsodium](http://doc.libsodium.org/).

Combine the source files by running:

    make
    
And directly drop `out/blobcrypt.c` and `out/blobcrypt.h` into your project.

Usage
=====

Encryption
----------

```c
int blobcrypt_encrypt_init(blobcrypt_encrypt_state *state,
                           int (*write_cb)(void *user_ptr,
                                           unsigned char *buf, size_t len),
                           int (*close_success_cb)(void *user_ptr),
                           int (*close_error_cb)(void *user_ptr),
                           void *user_ptr, unsigned long long total_len,
                           const unsigned char *k);
```                           

Initialize the encryption system.

`write_cb` is a pointer to a function reponsible for writing `len`
bytes from `buf` into the target file or memory region.
It must return `0` on success and `-1` on error. Partial writes are
not allowed.

`close_success_cb` is a pointer to a function being called after the
encrypted data has been successfully written. If the output is a file,
this function might rename a temporary file to its final name.

If the encryption process fails, `close_error_cb` will be called
instead of `close_success_cb`. If the output is a file,
`close_error_cb` should delete the temporary destination file.

`user_ptr` is a user-defined pointer passed to `write_cb`,
`close_success_cb`, and `close_error_cb`. It can be `NULL`.

`total_len` is the total number of bytes to encrypt.

`k` is a secret key, whose size is `blobcrypt_KEYBYTES` bytes.

The function returns `0` on success and `-1` on error.

```c
int blobcrypt_encrypt_update(blobcrypt_encrypt_state *state,
                             const unsigned char *in,
                             unsigned long long len);
```                             

The input data can be provided in any number of segments, of any size.
For each call of `blobcrypt_encrypt_update`, the application must
provide a pointer to the first byte of a segment `in` and the segment
length `len`.

The function returns `0` on success and `-1` on error.

```c
int blobcrypt_encrypt_final(blobcrypt_encrypt_state *state);
```

After `total_len` bytes have been pushed using
`blobcrypt_encrypt_update`, the function `blobcrypt_encrypt_final`
must be called.

It will finalize the last block and call either `close_success_cb` or
`close_error_cb`.

The function returns `0` on success and `-1` on error.

If any of these functions fail, subsequent calls to encryption
functions will return `-1` as well, and no more data will be written.

`close_error_cb` will be called instead of `close_success_cb` if a
previous operation fails, no matter what the function is.

Encrypting a message whose size is dynamic
------------------------------------------

If the size of a message is dynamic or not known when starting the
encryption process, the following function can be used in order to
output the header again, with an updated total length:

```c
int blobcrypt_encrypt_truncate(blobcrypt_encrypt_state *state,
                               unsigned long long total_len);
```

When the output is a file, a typical way to use this function is to
pass `blobcrypt_UNKNOWNSIZE` as the initial size, write the encrypted
data, rewind the file and update the header with the actual length:

```c
blobcrypt_encrypt_init();
blobcrypt_encrypt_update();
blobcrypt_encrypt_update();
...
rewind();
blobcrypt_encrypt_truncate();
blobcrypt_encrypt_final();
```

Decryption
----------

```c
int blobcrypt_decrypt_init(blobcrypt_decrypt_state *state,
                           int (*write_cb)(void *user_ptr,
                                           unsigned char *buf, size_t len),
                           int (*close_success_cb)(void *user_ptr),
                           int (*close_error_cb)(void *user_ptr),
                           void *user_ptr, unsigned long long total_len,
                           const unsigned char *k);
```

Initialize the decryption system.

`write_cb` is a pointer to a function reponsible for writing `len`
bytes from `buf` into the target file or memory region.
It must return `0` on success and `-1` on error. Partial writes are
not allowed.

`close_success_cb` is a pointer to a function being called after the
decrypted data has been successfully written. If the output is a file,
this function might rename a temporary file to its final name.

If the decryption process fails, `close_error_cb` will be called
instead of `close_success_cb`. If the output is a file,
`close_error_cb` should delete the temporary destination file.

`user_ptr` is a user-defined pointer passed to `write_cb`,
`close_success_cb`, and `close_error_cb`. It can be `NULL`.

`total_len` is the total number of bytes of the decrypted, if known in
advance. This is optional: if the size is not known in advance,
`total_len` should be set to `blobcrypt_UNKNOWNSIZE` instead.

Providing the expected size allows the decryption process return an
error as soon as the first header is decrypted if the size stored in
the header doesn't match the expected one.

`k` is a secret key, whose size is `blobcrypt_KEYBYTES` bytes.

The function returns `0` on success and `-1` on error.

```c
int blobcrypt_decrypt_update(blobcrypt_decrypt_state *state,
                             const unsigned char *in,
                             unsigned long long len);
```

The input data can be provided in any number of segments, of any size.
For each call of `blobcrypt_decrypt_update`, the application must
provide a pointer to the first byte of a segment `in` and the segment
length `len`.

The function returns `0` on success and `-1` on error.

```c
int blobcrypt_decrypt_final(blobcrypt_decrypt_state *state);
```

After all the input data have been pushed using
`blobcrypt_decrypt_update`, `blobcrypt_decrypt_final` must be called.

It will check that the expected number of bytes have been decrypted, and
call either `close_success_cb` or `close_error_cb`.

The function returns `0` on success and `-1` on error.

If any of these functions fail, subsequent calls to decryption
functions will return `-1` as well, and no more data will be written.

`close_error_cb` will be called instead of `close_success_cb` if a
previous operation fails, no matter what the function is.

Rationale for the API
=====================

The API was designed to be as safe as possible even if the application
doesn't systematically implement error handling.

In particular, the code flow is always the same no matter what failures
happen:

- `*_init()`
- `*_update()`
- `*_final()`

Ideally, the return code of each function call should be tested. If an
`*_update()` operation fails, the encryption/decryption process can be
aborted prematurely.

But not doing so will stop calling the `write_cb()` callback, and
safely propagate the failure state to subsequent function calls.

While suboptimal from a performance perspective, testing only the
return code of the call to `*_final()` remains safe.

Predictability: the `close_error_cb()` callback will only be called
by `*_final()`, and the only callback that can be called by
`*_update()` is `write_cb()`.

Closing a stream or a file descriptor can involve deallocating
resources, which can be tricky to do safely if it can happen at any time.

The blobcrypt API ensures that the operation (being `close_error_cb()`
or `close_success_cb()`) will always happen at the same place.

Finally, the API doesn't perform any memory allocations.

File format
===========

Although the implementation currently only supports sequential
read/write, the file format allows random access read, as well as
overwriting random blocks. Files can also be truncated and extended,
provided that the total length is updated in the header.

Header
------

Additional data section:

    File magic: Bl0Cry\x01\x00
    Header length: 4 bytes in little-endian format
    Additional data section length: 4 bytes in little-endian format
    Nonce: 24 bytes

Encrypted data section:

    Message ID: 32 bytes
    Block size: 8 bytes in little-endian format (currently: 65536)
    Total unencrypted message length: 8 bytes in little-endian format
    Authenticator: 16 bytes

Data blocks
-----------

    Nonce: 24 bytes
    Encrypted data: up to <block size> bytes
    Authenticator: 16 bytes

The authenticator is calculated using the following additional data,
that doesn't have to be stored in data blocks:

    Offset of the first byte of the block: 8 bytes in little-endian format
    Message ID: 32 bytes, stored in the header

AEAD construction
-----------------

The header and the data blocks are encrypted and authenticated using
an AEAD construction based on the ChaCha20-Poly1305 construction
defined by the IETF.

Given an optional 256-bit `message ID`, a 256-bit secret key `k` and a
192-bit nonce `nonce`, a subkey is calculated using the Blake2b hash
function with the following parameters:

    Personalization: 426c6f6243727970745f4c69622d0100 ("BlobCrypt_Lib-\01\00")
    Salt: 128 first bits of the message ID
    Key: k
    Data: first 96 bits of the nonce
    Output size: 256 bits

The encryption and authentication then use the construction described in the
ChaCha20-Poly1305 for IETF protocols RFC, with the following parameters:

    Key: subkey as described above
    Nonce: last 96 bits of the nonce

