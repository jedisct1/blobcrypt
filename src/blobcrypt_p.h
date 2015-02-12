
#define FILE_MAGIC "Bl0Cry\x01\x00"
#define HEADER_PUBBYTES (8U + 4U + 4U + block_NONCEBYTES)
#define HEADER_BYTES 104U
#define MAGIC_BYTES 8U
#define MESSAGE_ID_BYTES 32U

typedef struct blob_header {
    unsigned char magic[8U];
    unsigned char header_len[4U];
    unsigned char ad_len[4U];
    unsigned char nonce[block_NONCEBYTES];

    unsigned char message_id[MESSAGE_ID_BYTES];
    unsigned char block_size[8U];
    unsigned char total_len[8U];
    unsigned char auth[block_ABYTES];
} blob_header;

typedef struct block_ad {
    unsigned char offset[8U];
    unsigned char message_id[MESSAGE_ID_BYTES];
} block_ad;
