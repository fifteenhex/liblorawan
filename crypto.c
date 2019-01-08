#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <string.h>

#include "include/lorawan/crypto.h"
#include "include/lorawan/lorawan.h"

int crypto_encrypt_joinack(const unsigned char* key, void* data, size_t datalen,
		lorawan_writer writer, void* userdata) {
	int ret = LORAWAN_ERR;

	EVP_CIPHER_CTX* ctx = NULL;

	// This has to be a multiple of the AES block size
	if (datalen % 16 != 0)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if (!EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, NULL))
		goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	uint8_t tmp[16];
	int outlen;
	for (unsigned pos = 0; pos < datalen; pos += sizeof(tmp)) {
		int len = datalen - pos;
		if (len > sizeof(tmp))
			len = sizeof(tmp);

		if (!EVP_DecryptUpdate(ctx, tmp, &outlen, data + pos, len)) {
			ret = LORAWAN_CRYPTO_UPDTERR;
			goto out;
		}
		if ((ret = writer(tmp, outlen, userdata)) != LORAWAN_NOERR)
			goto out;
	}

	if (!EVP_DecryptFinal(ctx, tmp, &outlen)) {
		ret = LORAWAN_CRYPTO_FNLZERR;
		goto out;
	}
	if ((ret = writer(tmp, outlen, userdata)) != LORAWAN_NOERR)
		goto out;

	ret = LORAWAN_NOERR;

	out: if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

uint32_t crypto_mic_2(const void* key, size_t keylen, const void* data1,
		size_t data1len, const void* data2, size_t data2len) {
	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key, keylen, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, data1, data1len);
	if (data2 != NULL)
		CMAC_Update(ctx, data2, data2len);
	uint8_t mac[16];
	size_t maclen;
	CMAC_Final(ctx, mac, &maclen);
	CMAC_CTX_free(ctx);

	uint32_t mic;
	for (int i = 3; i >= 0; i--) {
		mic = mic << 8;
		mic |= mac[i];
	}
	return mic;
}

uint32_t crypto_mic(const void* key, size_t keylen, const void* data,
		size_t datalen) {
	return crypto_mic_2(key, keylen, data, datalen, NULL, 0);
}

#define SKEYPAD (SESSIONKEYLEN - (1 + APPNONCELEN + NETIDLEN + DEVNONCELEN))

static void crypto_calculatesessionkeys_key(const uint8_t* key,
		uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t* skey,
		uint8_t kb) {

	uint8_t pad[SKEYPAD] = { 0 };

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, NULL);

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	int outlen;
	EVP_EncryptUpdate(ctx, skey, &outlen, &kb, sizeof(kb));
	skey += outlen;
	EVP_EncryptUpdate(ctx, skey, &outlen, (void*) &appnonce, APPNONCELEN);
	skey += outlen;
	EVP_EncryptUpdate(ctx, skey, &outlen, (void*) &netid, NETIDLEN);
	skey += outlen;
	EVP_EncryptUpdate(ctx, skey, &outlen, (void*) &devnonce, DEVNONCELEN);
	skey += outlen;
	EVP_EncryptUpdate(ctx, skey, &outlen, pad, sizeof(pad));
	skey += outlen;
	EVP_EncryptFinal(ctx, skey, &outlen);
	skey += outlen;
	EVP_CIPHER_CTX_free(ctx);
}

void crypto_calculatesessionkeys(const uint8_t* key, uint32_t appnonce,
		uint32_t netid, uint16_t devnonce, uint8_t* networkkey, uint8_t* appkey) {

	const uint8_t nwkbyte = 0x01;
	const uint8_t appbyte = 0x02;

	crypto_calculatesessionkeys_key(key, appnonce, netid, devnonce, networkkey,
			nwkbyte);
	crypto_calculatesessionkeys_key(key, appnonce, netid, devnonce, appkey,
			appbyte);
}

void crypto_randbytes(void* buff, size_t len) {
	RAND_bytes(buff, len);
}

void crypto_fillinblock(uint8_t* block, uint8_t firstbyte, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte) {
	// 5 - dir
	// 6 - devaddr
	// 10 - fcnt
	// 15 - len
	memset(block, 0, BLOCKLEN);
	block[0] = firstbyte;
	block[5] = dir;
	memcpy(block + 6, &devaddr, sizeof(devaddr));
	memcpy(block + 10, &fcnt, sizeof(fcnt));
	block[15] = lastbyte;
}

void crypto_fillinblock_updownlink(uint8_t* block, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte) {
	crypto_fillinblock(block, 0x49, dir, devaddr, fcnt, lastbyte);
}

static void crypto_endecryptpayload_generates(const uint8_t* key,
		const uint8_t* ai, uint8_t* s) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	int outlen;
	EVP_EncryptUpdate(ctx, s, &outlen, ai, BLOCKLEN);
	EVP_EncryptFinal(ctx, s + outlen, &outlen);
	EVP_CIPHER_CTX_free(ctx);
}

void crypto_endecryptpayload(const uint8_t* key, bool downlink,
		uint32_t devaddr, uint32_t fcnt, const uint8_t* in, uint8_t* out,
		size_t len) {
	for (int i = 0; (i * 16) < len; i++) {
		uint8_t ai[BLOCKLEN];
		crypto_fillinblock(ai, 0x1, downlink ? 1 : 0, devaddr, fcnt, i + 1);
		uint8_t s[BLOCKLEN];
		crypto_endecryptpayload_generates(key, ai, s);
		for (int j = 0; j < 16; j++) {
			int offset = (i * 16) + j;
			if (offset == len)
				break;
			out[offset] = in[offset] ^ s[j];
		}

	}
}
