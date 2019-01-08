#include <string.h>

#include "include/lorawan/lorawan.h"
#include "include/lorawan/crypto.h"
#include "include/lorawan/packet.h"

#define COPYANDINC(dst, src)	memcpy(dst, src, sizeof(*dst));\
									src += sizeof(*dst)

int packet_build_joinreq(uint64_t appeui, uint64_t deveui, uint16_t devnonce,
		lorawan_writer cb, void* userdata) {
	int ret = LORAWAN_ERR;
	uint8_t mhdr = 0;
	lorawan_writer_appendu8(mhdr, cb, userdata);
	lorawan_writer_appendu64(appeui, cb, userdata);
	lorawan_writer_appendu64(deveui, cb, userdata);
	lorawan_writer_appendu16(devnonce, cb, userdata);
	uint32_t mic = 0xff00ff00;
	lorawan_writer_appendu32(mic, cb, userdata);
	ret = LORAWAN_NOERR;
	return ret;
}

int packet_build_joinresponse(uint32_t appnonce, uint32_t devaddr,
		const uint32_t* extrachannels, const char* appkey, lorawan_writer cb,
		void* userdata) {

	int ret = LORAWAN_ERR;

	// Because everything except MHDR is encrypted we need to
	// build an intermediate version first.
	LORAWAN_WRITER_STACKBUFFER(buffer, LORAWAN_JOINACK_MAXSZ);

	uint8_t mhdr = (MHDR_MTYPE_JOINACK << MHDR_MTYPE_SHIFT);
	lorawan_writer_appendu8(mhdr, lorawan_write_simple_buffer_callback,
			&buffer);
	lorawan_writer_appendu24(appnonce, lorawan_write_simple_buffer_callback,
			&buffer);
	uint32_t netid = 0;
	lorawan_writer_appendu24(netid, lorawan_write_simple_buffer_callback,
			&buffer);
	lorawan_writer_appendu32(devaddr, lorawan_write_simple_buffer_callback,
			&buffer);
	uint8_t dlsettings = 0;
	lorawan_writer_appendu8(dlsettings, lorawan_write_simple_buffer_callback,
			&buffer);
	uint8_t rxdelay = 0;
	lorawan_writer_appendu8(rxdelay, lorawan_write_simple_buffer_callback,
			&buffer);

	if (extrachannels != NULL) {
		for (int i = 0; i < 5; i++)
			lorawan_writer_appendu24(*extrachannels++,
					lorawan_write_simple_buffer_callback, &buffer);
		lorawan_writer_appendu8(0, lorawan_write_simple_buffer_callback,
				&buffer);
	}

	uint32_t mic = crypto_mic(appkey, KEYLEN, buffer.data, buffer.pos);
	lorawan_writer_appendu32(mic, lorawan_write_simple_buffer_callback,
			&buffer);

	// steam header and encrypted body
	lorawan_writer_appendu8(mhdr, cb, userdata);
	ret = crypto_encrypt_joinack(appkey, buffer.data + 1, buffer.pos - 1, cb,
			userdata);

	//out:
	return ret;
}

int packet_pack(struct packet_unpacked* unpacked, uint8_t* nwksk,
		uint8_t* appsk, lorawan_writer cb, void* userdata) {
	int ret = LORAWAN_NOERR;
	switch (unpacked->type) {
	case MHDR_MTYPE_UNCNFUP:
	case MHDR_MTYPE_UNCNFDN:
	case MHDR_MTYPE_CNFUP:
	case MHDR_MTYPE_CNFDN:
		/*pkt = packet_build_data(unpacked->type, unpacked->data.devaddr,
		 unpacked->data.adr, unpacked->data.ack,
		 unpacked->data.framecount, unpacked->data.port,
		 unpacked->data.payload, unpacked->data.payloadlen, keys,
		 &pktlen);
		 packet_debug(pkt, pktlen);*/
		break;
	default:
		ret = LORAWAN_PACKET_UKNWNTYPE;
		goto out;
		break;
	}

	out: return ret;
}

int packet_unpack(uint8_t* data, size_t len, struct packet_unpacked* result) {
	uint8_t* dataend = data + (len - sizeof(result->mic));

	uint8_t mhdr = *data++;
	result->type = LORAWAN_TYPE(mhdr);

	switch (result->type) {
	case MHDR_MTYPE_JOINREQ: {
		COPYANDINC(&result->joinreq.appeui, data);
		COPYANDINC(&result->joinreq.deveui, data);
		COPYANDINC(&result->joinreq.devnonce, data);
	}
		break;
	case MHDR_MTYPE_JOINACK:
		break;
	case MHDR_MTYPE_UNCNFUP:
	case MHDR_MTYPE_UNCNFDN:
	case MHDR_MTYPE_CNFUP:
	case MHDR_MTYPE_CNFDN: {
		COPYANDINC(&result->data.devaddr, data);

		// parse fctrl byte
		uint8_t fctrl = *data++;
		result->data.foptscount = fctrl & LORAWAN_FHDR_FCTRL_FOPTLEN_MASK;
		result->data.adr = (fctrl & LORAWAN_FHDR_FCTRL_ADR) ? 1 : 0;
		result->data.adrackreq = (fctrl & LORAWAN_FHDR_FCTRL_ADRACKREQ) ? 1 : 0;
		result->data.ack = (fctrl & LORAWAN_FHDR_FCTRL_ACK) ? 1 : 0;
		result->data.pending = (fctrl & LORAWAN_FHDR_FCTRL_FPENDING) ? 1 : 0;

		COPYANDINC(&result->data.framecount, data);
		for (int i = 0; i < result->data.foptscount; i++)
			result->data.fopts[i] = *data++;

		// port and payload are optional
		if (data != dataend) {
			result->data.port = *data++;
			result->data.payload = data;
			result->data.payloadlen = dataend - data;
			data += result->data.payloadlen;
		} else {
			result->data.port = 0;
			result->data.payload = NULL;
			result->data.payloadlen = 0;
		}
	}
		break;
	default:
		return LORAWAN_PACKET_UKNWNTYPE;
	}

	COPYANDINC(&result->mic, data);

	return LORAWAN_NOERR;
}
