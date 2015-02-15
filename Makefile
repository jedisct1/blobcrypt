
HEADERS = out/blobcrypt.h
HEADERS_P = src/headers.h src/bytealign.h src/block_aead.h src/blobcrypt_p.h
SRC = src/block_aead.c src/blobcrypt_decrypt.c src/blobcrypt_encrypt.c
COMBINED = out/blobcrypt.c
EXAMPLE = example/example
EXAMPLE_SRC = example/example.c example/helpers.c example/key_derivation.c
CFLAGS = -std=c99 -Wall -W -O -I. -Iout -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lsodium
CAT = cat
RM = rm -f

all: $(COMBINED) $(EXAMPLE)

$(COMBINED): $(HEADERS) $(HEADERS_P) $(SRC) Makefile
	$(CAT) $(HEADERS_P) $(SRC) > $(COMBINED)

$(EXAMPLE): $(COMBINED) $(EXAMPLE_SRC) Makefile
	$(CC) $(CFLAGS) -o $(EXAMPLE) $(EXAMPLE_SRC) $(COMBINED) $(LDFLAGS)

clean:
	$(RM) $(COMBINED) $(EXAMPLE)
