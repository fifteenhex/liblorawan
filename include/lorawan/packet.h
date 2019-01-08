#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "lorawan.h"
#include "writer.h"

struct packet_unpacked_data {
	uint32_t devaddr;
	bool adr, adrackreq, ack, pending;
	uint8_t foptscount;
	uint8_t fopts[16];
	uint16_t framecount;
	uint8_t port;
	uint8_t* payload;
	size_t payloadlen;
};

struct packet_unpacked_joinreq {
	uint64_t appeui;
	uint64_t deveui;
	uint16_t devnonce;
};

struct packet_unpacked {
	uint8_t type;
	struct packet_unpacked_data data;
	struct packet_unpacked_joinreq joinreq;
	uint32_t mic;
};

int packet_pack(struct packet_unpacked* unpacked, uint8_t* nwksk,
		uint8_t* appsk, lorawan_writer cb, void* userdata);
int packet_unpack(uint8_t* data, size_t len, struct packet_unpacked* result);
int packet_build_joinreq(uint64_t appeui, uint64_t deveui, uint16_t devnonce,
		lorawan_writer cb, void* userdata);
int packet_build_joinresponse(uint32_t appnonce, uint32_t devaddr,
		const uint32_t* extrachannels, const char* appkey, lorawan_writer cb,
		void* userdata);
