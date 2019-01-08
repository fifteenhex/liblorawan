#pragma once

#include <stdint.h>
#include <string.h>

#include "lorawan.h"

struct lorawan_writer_simple_buffer {
	uint8_t* data;
	size_t len;
	unsigned pos;
};

#define LORAWAN_WRITE_STACKBUFFER(name, size) uint8_t name_buff[size];\
												struct lorawan_writer_simple_buffer buffer = { .data = name_buff, .len = sizeof(name_buff),.pos = 0}

typedef int (*lorawan_writer)(uint8_t* data, size_t len, void* userdata);

static int __attribute__((unused)) lorawan_write_simple_buffer_callback(
		uint8_t* data, size_t len, void* userdata) {
	struct lorawan_writer_simple_buffer* pb = userdata;
	if (pb->pos + len > pb->len)
		return LORAWAN_ERR;
	memcpy(pb->data + pb->pos, data, len);
	pb->pos += len;
	return LORAWAN_NOERR;
}
static void lorawan_writer_appendbuff(uint8_t* buff, size_t len,
		lorawan_writer cb, void* userdata) {
	cb(buff, len, userdata);
}

static void __attribute__((unused)) lorawan_writer_appendun(uint32_t value,
		unsigned bytes, lorawan_writer cb, void* userdata) {
	for (int i = 0; i < bytes; i++) {
		uint8_t byte = (value >> (i * 8) & 0xff);
		cb(&byte, 1, userdata);
	}
}

static void __attribute__((unused)) lorawan_writer_appendu32(uint32_t value,
		lorawan_writer cb, void* userdata) {
	lorawan_writer_appendun(value, 4, cb, userdata);
}

static void __attribute__((unused)) lorawan_writer_appendu24(uint32_t value,
		lorawan_writer cb, void* userdata) {
	lorawan_writer_appendun(value, 3, cb, userdata);
}

static void __attribute__((unused)) lorawan_writer_appendu16(uint16_t value,
		lorawan_writer cb, void* userdata) {
	lorawan_writer_appendun(value, 2, cb, userdata);
}

static void __attribute__((unused)) lorawan_writer_appendu8(uint8_t value,
		lorawan_writer cb, void* userdata) {
	lorawan_writer_appendun(value, 1, cb, userdata);
}
