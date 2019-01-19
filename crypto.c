#include <openssl/rand.h>
#include <string.h>

#include "include/lorawan/crypto.h"
#include "include/lorawan/lorawan.h"

struct __lorawan_crypto_mic_context {
	CMAC_CTX* cmac_cntx;
};

static void crypto_fillin_ablock(uint8_t* block, uint8_t firstbyte, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt) {
	// 5 - dir
	// 6 - devaddr
	// 10 - fcnt
	// 15 - len
	memset(block, 0, BLOCKLEN);
	block[0] = firstbyte;
	block[5] = dir;
	memcpy(block + 6, &devaddr, sizeof(devaddr));
	memcpy(block + 10, &fcnt, sizeof(fcnt));

}

static void crypto_update_ablock(uint8_t* block, uint8_t lastbyte) {
	block[15] = lastbyte;
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

static int crypto_endecrypt_joinack(const unsigned char* key, void* data,
		size_t datalen, bool decrypt, lorawan_writer writer, void* userdata) {
	int ret = LORAWAN_ERR;

	EVP_CIPHER_CTX* ctx = NULL;

	// This has to be a multiple of the AES block size
	if (datalen % 16 != 0)
		goto out;

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	if (decrypt) {
		if (!EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, NULL))
			goto out;
	} else {
		if (!EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, NULL))
			goto out;
	}

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	uint8_t tmp[16];
	int outlen;
	for (unsigned pos = 0; pos < datalen; pos += sizeof(tmp)) {
		int len = datalen - pos;
		if (len > sizeof(tmp))
			len = sizeof(tmp);

		if (decrypt) {
			if (!EVP_EncryptUpdate(ctx, tmp, &outlen, data + pos, len)) {
				ret = LORAWAN_CRYPTO_UPDTERR;
				goto out;
			}
		} else {
			if (!EVP_DecryptUpdate(ctx, tmp, &outlen, data + pos, len)) {
				ret = LORAWAN_CRYPTO_UPDTERR;
				goto out;
			}
		}
		if ((ret = writer(tmp, outlen, userdata)) != LORAWAN_NOERR)
			goto out;
	}

	if (decrypt) {
		if (!EVP_EncryptFinal(ctx, tmp, &outlen)) {
			ret = LORAWAN_CRYPTO_FNLZERR;
			goto out;
		}
	} else {
		if (!EVP_DecryptFinal(ctx, tmp, &outlen)) {
			ret = LORAWAN_CRYPTO_FNLZERR;
			goto out;
		}
	}

	if ((ret = writer(tmp, outlen, userdata)) != LORAWAN_NOERR)
		goto out;

	ret = LORAWAN_NOERR;

	out: if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int crypto_encrypt_joinack(const unsigned char* key, void* data, size_t datalen,
		lorawan_writer writer, void* userdata) {
	return crypto_endecrypt_joinack(key, data, datalen, false, writer, userdata);
}

int lorawan_crypto_decrypt_joinack(const unsigned char* key, void* data,
		size_t datalen, lorawan_writer writer, void* userdata) {
	return crypto_endecrypt_joinack(key, data, datalen, true, writer, userdata);
}

lorawan_crypto_mic_context* lorawan_crypto_mic_start(const uint8_t* key) {
	CMAC_CTX *cntx = CMAC_CTX_new();
	CMAC_Init(cntx, key, KEYLEN, EVP_aes_128_cbc(), NULL);
	return cntx;
}

int lorawan_crypto_mic_update(lorawan_crypto_mic_context* cntx,
		const uint8_t* data, size_t datalen) {
	CMAC_Update(cntx, data, datalen);
	return 0;
}

uint32_t lorawan_crypto_mic_finalise(lorawan_crypto_mic_context* cntx) {
	uint8_t mac[16];
	size_t maclen;
	CMAC_Final(cntx, mac, &maclen);
	CMAC_CTX_free(cntx);

	uint32_t mic;
	for (int i = 3; i >= 0; i--) {
		mic = mic << 8;
		mic |= mac[i];
	}

	return mic;
}

uint32_t lorawan_crypto_mic_simple(const void* key, const void* data,
		size_t datalen) {
	lorawan_crypto_mic_context* cntx = lorawan_crypto_mic_start(key);
	lorawan_crypto_mic_update(cntx, data, datalen);
	return lorawan_crypto_mic_finalise(cntx);
}

uint32_t lorawan_crypto_mic_simple2(const void* key, size_t keylen,
		const void* data1, size_t data1len, const void* data2, size_t data2len) {
	lorawan_crypto_mic_context* cntx = lorawan_crypto_mic_start(key);
	lorawan_crypto_mic_update(cntx, data1, data1len);
	lorawan_crypto_mic_update(cntx, data2, data2len);
	return lorawan_crypto_mic_finalise(cntx);
}

static void lorawan_crypto_calculatesessionkeys_key(const uint8_t* key,
		uint8_t kb, uint32_t appnonce, uint32_t netid, uint16_t devnonce,
		uint8_t* skey) {

	LORAWAN_WRITER_STACKBUFFER(keymaterial, SESSIONKEYLEN);
	lorawan_writer_appendu8(kb, lorawan_write_simple_buffer_callback,
			&keymaterial);
	lorawan_writer_appendu24(appnonce, lorawan_write_simple_buffer_callback,
			&keymaterial);
	lorawan_writer_appendu24(netid, lorawan_write_simple_buffer_callback,
			&keymaterial);
	lorawan_writer_appendu16(devnonce, lorawan_write_simple_buffer_callback,
			&keymaterial);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, NULL);

	EVP_CIPHER_CTX_set_padding(ctx, 0);
	int outlen;
	// notice that len is used here and not pos
	// the keymaterial needs to be padded with zeros.
	// the buffer above is initialised with zeros so we
	// get the padding for free
	EVP_EncryptUpdate(ctx, skey, &outlen, keymaterial.data, keymaterial.len);
	skey += outlen;
	EVP_EncryptFinal(ctx, skey, &outlen);
	EVP_CIPHER_CTX_free(ctx);
}

void lorawan_crypto_calculatesessionkeys(const uint8_t* key, uint32_t appnonce,
		uint32_t netid, uint16_t devnonce, uint8_t* networkkey, uint8_t* appkey) {
	const uint8_t nwkbyte = 0x01;
	const uint8_t appbyte = 0x02;

	lorawan_crypto_calculatesessionkeys_key(key, nwkbyte, appnonce, netid,
			devnonce, networkkey);
	lorawan_crypto_calculatesessionkeys_key(key, appbyte, appnonce, netid,
			devnonce, appkey);
}

void crypto_randbytes(void* buff, size_t len) {
	RAND_bytes(buff, len);
}

void crypto_fillinblock_updownlink(uint8_t* block, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte) {
	crypto_fillin_ablock(block, 0x49, dir, devaddr, fcnt);
	crypto_update_ablock(block, lastbyte);
}

int lorawan_crypto_endecryptpayload(const uint8_t* key, bool downlink,
		uint32_t devaddr, uint32_t fcnt, const uint8_t* in, size_t len,
		lorawan_writer writer, void* userdata) {
	int ret = LORAWAN_NOERR;
	uint8_t ai[BLOCKLEN];
	crypto_fillin_ablock(ai, 0x1, downlink ? 1 : 0, devaddr, fcnt);
	for (int i = 0; (i * 16) < len; i++) {
		crypto_update_ablock(ai, i + 1);
		uint8_t s[BLOCKLEN];
		crypto_endecryptpayload_generates(key, ai, s);
		for (int j = 0; j < 16; j++) {
			int offset = (i * 16) + j;
			if (offset == len)
				break;
			uint8_t v = in[offset] ^ s[j];
			if ((ret = writer(&v, sizeof(v), userdata)) != LORAWAN_NOERR)
				goto out;
		}
	}
	out: return ret;
}
