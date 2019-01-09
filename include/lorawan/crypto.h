#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/cmac.h>

#include "writer.h"

typedef CMAC_CTX lorawan_crypto_mic_context;

void crypto_randbytes(void* buff, size_t len);

void crypto_calculatesessionkeys(const uint8_t* key, uint32_t appnonce,
		uint32_t netid, uint16_t devnonce, uint8_t* networkkey, uint8_t* appkey);

void crypto_fillinblock_updownlink(uint8_t* block, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte);

void crypto_endecryptpayload(const uint8_t* key, bool downlink,
		uint32_t devaddr, uint32_t fcnt, const uint8_t* in, uint8_t* out,
		size_t len);

int crypto_encrypt_joinack(const unsigned char* key, void* data, size_t datalen,
		lorawan_writer writer, void* userdata);

lorawan_crypto_mic_context* lorawan_crypto_mic_start(const uint8_t* key);
int lorawan_crypto_mic_update(lorawan_crypto_mic_context* cntx,
		const uint8_t* data, size_t datalen);
uint32_t lorawan_crypto_mic_finalise(lorawan_crypto_mic_context* cntx);
uint32_t lorawan_crypto_mic_simple(const void* key, const void* data,
		size_t datalen);
uint32_t lorawan_crypto_mic_simple2(const void* key, size_t keylen,
		const void* data1, size_t data1len, const void* data2, size_t data2len);
