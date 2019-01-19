#pragma once

#include <stdint.h>
#include <string.h>

#include "lorawan.h"

struct lorawan_writer_simple_buffer {
	uint8_t* data;
	size_t len;
	unsigned pos;
};

#define LORAWAN_WRITER_STACKBUFFER(name, size) uint8_t name##_buff[size] = {0};\
												struct lorawan_writer_simple_buffer name = { .data = name##_buff, .len = sizeof(name##_buff),.pos = 0}

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
static int __attribute__((unused)) lorawan_writer_appendbuff(uint8_t* buff,
		size_t len, lorawan_writer cb, void* userdata) {
	return cb(buff, len, userdata);
}

static int __attribute__((unused)) lorawan_writer_appendun(uint64_t value,
		unsigned bytes, lorawan_writer cb, void* userdata) {
	int ret = LORAWAN_NOERR;
	for (int i = 0; i < bytes; i++) {
		uint8_t byte = (value >> (i * 8) & 0xff);
		if ((ret = cb(&byte, 1, userdata)) != LORAWAN_NOERR)
			break;
	}
	return ret;
}

static int __attribute__((unused)) lorawan_writer_appendu64(uint64_t value,
		lorawan_writer cb, void* userdata) {
	return lorawan_writer_appendun(value, 8, cb, userdata);
}

static int __attribute__((unused)) lorawan_writer_appendu32(uint32_t value,
		lorawan_writer cb, void* userdata) {
	return lorawan_writer_appendun(value, 4, cb, userdata);
}

static int __attribute__((unused)) lorawan_writer_appendu24(uint32_t value,
		lorawan_writer cb, void* userdata) {
	return lorawan_writer_appendun(value, 3, cb, userdata);
}

static int __attribute__((unused)) lorawan_writer_appendu16(uint16_t value,
		lorawan_writer cb, void* userdata) {
	return lorawan_writer_appendun(value, 2, cb, userdata);
}

static int __attribute__((unused)) lorawan_writer_appendu8(uint8_t value,
		lorawan_writer cb, void* userdata) {
	return lorawan_writer_appendun(value, 1, cb, userdata);
}
