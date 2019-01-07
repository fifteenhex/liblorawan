#pragma once

#include <stdbool.h>

uint32_t crypto_mic_2(const void* key, size_t keylen, const void* data1,
		size_t data1len, const void* data2, size_t data2len);
uint32_t crypto_mic(const void* key, size_t keylen, const void* data,
		size_t datalen);
void crypto_encryptfordevice(const char* key, void* data, size_t datalen,
		void* dataout);
void crypto_randbytes(void* buff, size_t len);

void crypto_calculatesessionkeys(const uint8_t* key, uint32_t appnonce,
		uint32_t netid, uint16_t devnonce, uint8_t* networkkey, uint8_t* appkey);

void crypto_fillinblock(uint8_t* block, uint8_t firstbyte, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte);
void crypto_fillinblock_updownlink(uint8_t* block, uint8_t dir,
		uint32_t devaddr, uint32_t fcnt, uint8_t lastbyte);

void crypto_endecryptpayload(const uint8_t* key, bool downlink,
		uint32_t devaddr, uint32_t fcnt, const uint8_t* in, uint8_t* out,
		size_t len);
