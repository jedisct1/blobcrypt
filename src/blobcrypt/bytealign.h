
static inline void
_u64_le_from_ull(unsigned char out[8U], unsigned long long x)
{
    out[0] = (unsigned char) (x & 0xff); x >>= 8;
    out[1] = (unsigned char) (x & 0xff); x >>= 8;
    out[2] = (unsigned char) (x & 0xff); x >>= 8;
    out[3] = (unsigned char) (x & 0xff); x >>= 8;
    out[4] = (unsigned char) (x & 0xff); x >>= 8;
    out[5] = (unsigned char) (x & 0xff); x >>= 8;
    out[6] = (unsigned char) (x & 0xff); x >>= 8;
    out[7] = (unsigned char) (x & 0xff);
}

static inline unsigned long long
_ull_from_u64_le(const unsigned char in[8U])
{
    unsigned long long x;

    x  = in[7]; x <<= 8;
    x |= in[6]; x <<= 8;
    x |= in[5]; x <<= 8;
    x |= in[4]; x <<= 8;
    x |= in[3]; x <<= 8;
    x |= in[2]; x <<= 8;
    x |= in[1]; x <<= 8;
    x |= in[0];

    return x;
}

static inline void
_u32_le_from_ul(unsigned char out[4U], unsigned long x)
{
    out[0] = (unsigned char) (x & 0xff); x >>= 8;
    out[1] = (unsigned char) (x & 0xff); x >>= 8;
    out[2] = (unsigned char) (x & 0xff); x >>= 8;
    out[3] = (unsigned char) (x & 0xff);
}

static inline unsigned long
_ul_from_u32_le(const unsigned char in[4U])
{
    unsigned long x;

    x  = in[3]; x <<= 8;
    x |= in[2]; x <<= 8;
    x |= in[1]; x <<= 8;
    x |= in[0];

    return x;
}
