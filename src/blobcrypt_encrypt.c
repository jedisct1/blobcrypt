
static int
_blobcrypt_encrypt_sinkhole_write_cb(void *user_ptr, unsigned char *buf, size_t len)
{
    (void) user_ptr;
    (void) buf;
    (void) len;

    return -1;
}

static void
_blobcrypt_encrypt_sinkhole(blobcrypt_encrypt_state *state)
{
    sodium_memzero(state->k, sizeof state->k);
    sodium_memzero(state->message_id, sizeof state->message_id);
    state->write_cb = _blobcrypt_encrypt_sinkhole_write_cb;
}

static int
_write_header(blobcrypt_encrypt_state *state)
{
    blob_header        *header;
    unsigned long long  clen;

    assert(sizeof header->nonce == block_NONCEBYTES);
    assert(sizeof state->buf >= sizeof *header);
    assert(sizeof state->message_id == MESSAGE_ID_BYTES);
    assert(state->block_size <= UINT64_MAX);
    assert(state->block_size >= HEADER_BYTES);
    assert(state->total_len <= UINT64_MAX);
    assert(state->offset == 0U);

    /* additional data: 40 bytes (HEADER_PUBBYTES) */
    header = (blob_header *) (void *) state->buf;
    memcpy(header->magic, FILE_MAGIC, sizeof header->magic);
    _u32_le_from_ul(header->header_len, HEADER_BYTES);
    _u32_le_from_ul(header->ad_len, HEADER_PUBBYTES);
    randombytes_buf(header->nonce, sizeof header->nonce);

    /* secret data: 48 bytes (HEADER_BYTES - HEADER_PUBBYTES - block_ABYTES) */
    memcpy(header->message_id, state->message_id, sizeof header->message_id);
    _u64_le_from_ull(header->block_size,
                     (unsigned long long) state->block_size);
    _u64_le_from_ull(header->total_len, state->total_len);

    if (block_encrypt(header->message_id, &clen, header->message_id,
                      HEADER_BYTES - HEADER_PUBBYTES - block_ABYTES,
                      header->magic, HEADER_PUBBYTES, NULL, header->nonce,
                      state->k) != 0) {
        _blobcrypt_encrypt_sinkhole(state);
        return -1;
    }
    assert(HEADER_BYTES == HEADER_PUBBYTES + clen);

    return state->write_cb(state->user_ptr, state->buf, HEADER_BYTES);
}

static int
_blobcrypt_encrypt_flush(blobcrypt_encrypt_state *state)
{
    block_ad           ad;
    unsigned long long clen;
    size_t             plen = state->buf_pos;

    if (plen == 0U) {
        return 0;
    }
    randombytes_buf(state->nonce, sizeof state->nonce);
    _u64_le_from_ull(ad.offset, state->offset);
    memcpy(ad.message_id, state->message_id, sizeof ad.message_id);
    if (block_encrypt(state->buf, &clen, state->buf, plen,
                      (unsigned char *) (void *) &ad, sizeof ad,
                      state->message_id, state->nonce, state->k) != 0) {
        sodium_memzero(ad.message_id, sizeof ad.message_id);
        _blobcrypt_encrypt_sinkhole(state);
        return -1;
    }
    sodium_memzero(ad.message_id, sizeof ad.message_id);
    assert(clen == plen + block_ABYTES);
    if (state->write_cb(state->user_ptr, state->nonce,
                        (sizeof state->nonce) + (size_t) clen) != 0) {
        _blobcrypt_encrypt_sinkhole(state);
        return -1;
    }
    assert(state->total_len >= plen);
    assert(state->offset <= state->total_len - plen);
    state->buf_pos = 0U;
    state->offset += plen;

    return 0;
}

static int
_blobcrypt_encrypt_write_block(blobcrypt_encrypt_state *state)
{
    if (state->buf_pos < state->block_size) {
        return 0;
    }
    return _blobcrypt_encrypt_flush(state);
}

size_t
blobcrypt_message_block_size(const blobcrypt_encrypt_state *state)
{
    assert(state->block_size > 0U);
    assert(state->block_size <= SSIZE_MAX);

    return state->block_size;
}

size_t
blobcrypt_ciphertext_block_size(const blobcrypt_encrypt_state *state)
{
    if (state->block_size <= 0U) {
        return state->block_size;
    }
    assert(state->block_size <= SSIZE_MAX - block_ABYTES);

    return state->block_size + block_ABYTES;
}

int
blobcrypt_encrypt_init(blobcrypt_encrypt_state *state,
                       int (*write_cb)(void *user_ptr,
                                       unsigned char *buf, size_t len),
                       int (*close_success_cb)(void *user_ptr),
                       int (*close_error_cb)(void *user_ptr),
                       void *user_ptr, unsigned long long total_len,
                       const unsigned char *k)
{
    (void) sizeof(int[blobcrypt_KEYBYTES == block_KEYBYTES ? 1 : -1]);
    assert(sizeof state->k == blobcrypt_KEYBYTES);
    assert(sizeof state->message_id == MESSAGE_ID_BYTES);
    assert(sizeof state->nonce == block_NONCEBYTES);
    assert(sizeof state->buf == blobcrypt_BLOCKSIZE);
    assert(sizeof state->auth == block_ABYTES);

    if (total_len > UINT64_MAX || blobcrypt_BLOCKSIZE > UINT64_MAX ||
        blobcrypt_BLOCKSIZE > SSIZE_MAX || blobcrypt_BLOCKSIZE > block_MAXBYTES ||
        blobcrypt_BLOCKSIZE < HEADER_BYTES) {
        errno = EFBIG;
        _blobcrypt_encrypt_sinkhole(state);
        return -1;
    }
    memset(state->buf, 0, sizeof state->buf);
    state->write_cb = write_cb;
    state->close_success_cb = close_success_cb;
    state->close_error_cb = close_error_cb;
    state->user_ptr = user_ptr;
    state->buf_pos = 0U;
    state->state = -1;
    state->block_size = blobcrypt_BLOCKSIZE;
    state->total_len = total_len;
    state->offset = 0U;
    memmove(state->k, k, blobcrypt_KEYBYTES);
    randombytes_buf(state->message_id, sizeof state->message_id);

    return _write_header(state);
}

int
blobcrypt_encrypt_update(blobcrypt_encrypt_state *state,
                         const unsigned char *in,
                         unsigned long long len)
{
    size_t plen;
    size_t remaining;

    assert(state->block_size <= sizeof state->buf);
    while (len > 0U) {
        assert(state->buf_pos <= state->block_size);
        remaining = state->block_size - state->buf_pos;
        if (len > remaining) {
            plen = remaining;
        } else {
            plen = (size_t) len;
        }
        memcpy(state->buf + state->buf_pos, in, plen);
        state->buf_pos += plen;
        in += plen;
        len -= plen;
        _blobcrypt_encrypt_write_block(state);
    }
    return 0;
}

int
blobcrypt_encrypt_final(blobcrypt_encrypt_state *state)
{
    int ret;

    _blobcrypt_encrypt_flush(state);
    if (state->write_cb == _blobcrypt_encrypt_sinkhole_write_cb) {
        state->close_error_cb(state->user_ptr);
        ret = -1;
    } else {
        ret = state->close_success_cb(state->user_ptr);
    }
    sodium_memzero(state, sizeof *state);

    return ret;
}
