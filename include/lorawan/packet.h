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

// packet builders
int lorawan_packet_build_joinreq(uint8_t* key, uint64_t appeui, uint64_t deveui,
		uint16_t devnonce, lorawan_writer cb, void* userdata);
int lorawan_packet_build_joinresponse(uint32_t appnonce, uint32_t devaddr,
		const uint32_t* extrachannels, const uint8_t* appkey, lorawan_writer cb,
		void* userdata);
int lorawan_packet_build_data(uint8_t type, uint32_t devaddr, bool adr,
bool adrackreq, bool ack, bool fpending, uint32_t framecounter, uint8_t port,
		const uint8_t* payload, size_t payloadlen, uint8_t* nwksk,
		uint8_t* appsk, lorawan_writer cb, void* userdata);

bool lorawan_packet_verifymic(uint8_t* key, uint8_t* data, size_t len,
		uint32_t* mic, uint32_t* actualmic);

//junk
int packet_pack(struct packet_unpacked* unpacked, uint8_t* nwksk,
		uint8_t* appsk, lorawan_writer cb, void* userdata);
int packet_unpack(uint8_t* data, size_t len, struct packet_unpacked* result);
