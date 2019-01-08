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
