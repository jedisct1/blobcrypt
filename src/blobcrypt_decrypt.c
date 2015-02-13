
static int
_blobcrypt_decrypt_sinkhole_write_cb(void *user_ptr, unsigned char *buf, size_t len)
{
    (void) user_ptr;
    (void) buf;
    (void) len;

    return -1;
}

static void
_blobcrypt_decrypt_sinkhole(blobcrypt_decrypt_state *state)
{
    sodium_memzero(state->k, sizeof state->k);
    sodium_memzero(state->message_id, sizeof state->message_id);
    state->write_cb = _blobcrypt_decrypt_sinkhole_write_cb;
}

static int
_blobcrypt_decrypt_flush(blobcrypt_decrypt_state *state)
{
    block_ad           ad;
    unsigned long long plen;
    size_t             clen;

    assert(state->buf_pos > (sizeof state->nonce) + (sizeof state->auth));
    clen = state->buf_pos - (sizeof state->nonce);
    _u64_le_from_ull(ad.offset, state->offset);
    memcpy(ad.message_id, state->message_id, sizeof ad.message_id);
    if (block_decrypt(state->buf, &plen, state->buf, clen,
                      (unsigned char *) (void *) &ad, sizeof ad,
                      state->message_id, state->nonce, state->k) != 0) {
        sodium_memzero(ad.message_id, sizeof ad.message_id);
        _blobcrypt_decrypt_sinkhole(state);
        return -1;
    }
    sodium_memzero(ad.message_id, sizeof ad.message_id);
    assert(plen == clen - (sizeof state->auth));
    if (state->write_cb(state->user_ptr, state->buf, (size_t) plen) != 0) {
        _blobcrypt_decrypt_sinkhole(state);
        return -1;
    }
    assert(state->total_len >= plen);
    assert(state->offset <= state->total_len - plen);
    state->buf_pos = 0U;
    state->offset += plen;

    return 0;
}

static int
_blobcrypt_decrypt_read_header(blobcrypt_decrypt_state *state)
{
    blob_header        header;
    unsigned long long block_size_ull;
    unsigned long long total_len_advertised;
    size_t             ad_len;
    size_t             header_len;
    size_t             header_secbytes;

    if (state->buf_pos < HEADER_PUBBYTES) {
        return 0;
    }
    if (memcmp(state->nonce, FILE_MAGIC, sizeof FILE_MAGIC - 1U) != 0) {
        return -1;
    }
    header_len = (size_t) _ul_from_u32_le(state->nonce + MAGIC_BYTES);
    if (header_len <= HEADER_PUBBYTES) {
        return -1;
    }
    if (header_len != HEADER_BYTES) {
        return -1;
    }
    if (state->buf_pos < header_len) {
        return 0;
    }
    assert(header_len == sizeof header);
    memcpy(&header, state->nonce, sizeof header);
    ad_len = _ul_from_u32_le(header.ad_len);
    if (header_len <= ad_len ||
        ad_len < MAGIC_BYTES + 4U + 4U + block_NONCEBYTES) {
        return -1;
    }
    if (ad_len != HEADER_PUBBYTES) {
        return -1;
    }
    header_secbytes = header_len - ad_len;
    if (block_decrypt(header.message_id, NULL, header.message_id,
                      header_secbytes, header.magic, ad_len, NULL,
                      header.nonce, state->k) != 0) {
        return -1;
    }
    total_len_advertised = _ull_from_u64_le(header.total_len);
    if (state->total_len != blobcrypt_UNKNOWNSIZE &&
        total_len_advertised != state->total_len) {
        sodium_memzero(&header, sizeof header);
        return -1;
    }
    state->total_len = _ull_from_u64_le(header.total_len);
    if (state->total_len >=
        ULLONG_MAX - (block_NONCEBYTES + block_ABYTES) - header_len) {
        sodium_memzero(&header, sizeof header);
        return -1;
    }
    block_size_ull = _ull_from_u64_le(header.block_size);
    if (block_size_ull <= block_NONCEBYTES + block_ABYTES ||
        block_size_ull > block_MAXBYTES ||
        block_size_ull >= SIZE_MAX - (block_NONCEBYTES + block_ABYTES)) {
        sodium_memzero(&header, sizeof header);
        return -1;
    }
    state->block_size = (size_t) block_size_ull;
    memcpy(state->message_id, header.message_id, sizeof state->message_id);
    sodium_memzero(&header, sizeof header);

    assert(state->buf_pos >= header_len);
    memmove(state->nonce, state->nonce + header_len,
            state->buf_pos - header_len);
    state->buf_pos -= header_len;
    state->state = 2;

    return 0;
}

static int
_blobcrypt_decrypt_read_block(blobcrypt_decrypt_state *state)
{
    switch (state->state) {
    case 1:
        if (_blobcrypt_decrypt_read_header(state) != 0) {
            return -1;
        }
    case 2:
        if (state->buf_pos <= block_NONCEBYTES + block_ABYTES) {
            return 0;
        }
        assert(state->total_len > state->offset);
        if (state->buf_pos - (block_NONCEBYTES + block_ABYTES) >
            state->total_len - state->offset) {
            return -1;
        }
        if (state->buf_pos - (block_NONCEBYTES + block_ABYTES) ==
            state->total_len - state->offset) {
            state->state = 3;
            return _blobcrypt_decrypt_flush(state);
        }
        if (state->buf_pos < (sizeof state->nonce) + state->block_size +
            (sizeof state->auth)) {
            return 0;
        }
        return _blobcrypt_decrypt_flush(state);
    case 3:
        _blobcrypt_decrypt_sinkhole(state);
    }
    return -1;
}

int
blobcrypt_decrypt_init(blobcrypt_decrypt_state *state,
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
        blobcrypt_BLOCKSIZE > SIZE_MAX || blobcrypt_BLOCKSIZE > block_MAXBYTES ||
        blobcrypt_BLOCKSIZE < HEADER_BYTES) {
        errno = EFBIG;
        _blobcrypt_decrypt_sinkhole(state);
        return -1;
    }
    memset(state->buf, 0, sizeof state->buf);
    state->write_cb = write_cb;
    state->close_success_cb = close_success_cb;
    state->close_error_cb = close_error_cb;
    state->user_ptr = user_ptr;
    state->buf_pos = 0U;
    state->state = 1;
    state->block_size = blobcrypt_BLOCKSIZE;
    state->total_len = total_len;
    state->offset = 0U;
    memmove(state->k, k, blobcrypt_KEYBYTES);
    memset(state->message_id, 0, sizeof state->message_id);

    return 0;
}

int
blobcrypt_decrypt_update(blobcrypt_decrypt_state *state,
                         const unsigned char *in,
                         unsigned long long len)
{
    size_t plen;
    size_t remaining;

    assert(state->block_size <= sizeof state->buf);
    while (len > 0U) {
        assert(state->buf_pos <= (sizeof state->nonce) + state->block_size +
              (sizeof state->auth));
        remaining = (sizeof state->nonce) + state->block_size +
            (sizeof state->auth) - state->buf_pos;
        if (len > remaining) {
            plen = remaining;
        } else {
            plen = (size_t) len;
        }
        memcpy(state->nonce + state->buf_pos, in, plen);
        state->buf_pos += plen;
        in += plen;
        len -= plen;
        if (_blobcrypt_decrypt_read_block(state) != 0) {
            _blobcrypt_decrypt_sinkhole(state);
            return -1;
        }
    }
    return 0;
}

int
blobcrypt_decrypt_final(blobcrypt_decrypt_state *state)
{
    if (state->write_cb == _blobcrypt_decrypt_sinkhole_write_cb ||
        state->offset != state->total_len) {
        state->close_error_cb(state->user_ptr);
        return -1;
    }
    return state->close_success_cb(state->user_ptr);
}
