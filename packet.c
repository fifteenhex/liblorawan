#include <string.h>

#include "include/lorawan/lorawan.h"
#include "include/lorawan/crypto.h"
#include "include/lorawan/packet.h"

#define COPYANDINC(dst, src)	memcpy(dst, src, sizeof(*dst));\
									src += sizeof(*dst)

struct packet_mic_and_chained_cb {
	lorawan_crypto_mic_context* mic;
	lorawan_writer chained_writer;
	void* chained_userdata;
};

static int packet_write_micandchain(uint8_t* data, size_t len, void* userdata) {
	struct packet_mic_and_chained_cb* cbdata = userdata;
	lorawan_crypto_mic_update(cbdata->mic, data, len);
	return cbdata->chained_writer(data, len, cbdata->chained_userdata);
}

int packet_build_joinreq(uint8_t* key, uint64_t appeui, uint64_t deveui,
		uint16_t devnonce, lorawan_writer cb, void* userdata) {
	int ret = LORAWAN_ERR;

	lorawan_crypto_mic_context* miccntx = lorawan_crypto_mic_start(key);

	struct packet_mic_and_chained_cb cbdata = { .mic = miccntx,
			.chained_writer = cb, .chained_userdata = userdata };

	uint8_t mhdr = 0;
	lorawan_writer_appendu8(mhdr, packet_write_micandchain, &cbdata);
	lorawan_writer_appendu64(appeui, packet_write_micandchain, &cbdata);
	lorawan_writer_appendu64(deveui, packet_write_micandchain, &cbdata);
	lorawan_writer_appendu16(devnonce, packet_write_micandchain, &cbdata);

	uint32_t mic = lorawan_crypto_mic_finalise(miccntx);
	lorawan_writer_appendu32(mic, cb, userdata);
	ret = LORAWAN_NOERR;
	return ret;
}

int packet_build_joinresponse(uint32_t appnonce, uint32_t devaddr,
		const uint32_t* extrachannels, const uint8_t* appkey, lorawan_writer cb,
		void* userdata) {

	int ret = LORAWAN_ERR;

	// Because everything except MHDR is encrypted we need to
	// build an intermediate version first.
	LORAWAN_WRITER_STACKBUFFER(buffer, LORAWAN_JOINACK_MAXSZ);

	lorawan_crypto_mic_context* miccntx = lorawan_crypto_mic_start(appkey);
	struct packet_mic_and_chained_cb cbdata = { .mic = miccntx,
			.chained_writer = lorawan_write_simple_buffer_callback,
			.chained_userdata = &buffer };

	uint8_t mhdr = (MHDR_MTYPE_JOINACK << MHDR_MTYPE_SHIFT);
	lorawan_writer_appendu8(mhdr, packet_write_micandchain, &cbdata);
	lorawan_writer_appendu24(appnonce, packet_write_micandchain, &cbdata);
	uint32_t netid = 0;
	lorawan_writer_appendu24(netid, packet_write_micandchain, &cbdata);
	lorawan_writer_appendu32(devaddr, packet_write_micandchain, &cbdata);
	uint8_t dlsettings = 0;
	lorawan_writer_appendu8(dlsettings, packet_write_micandchain, &cbdata);
	uint8_t rxdelay = 0;
	lorawan_writer_appendu8(rxdelay, packet_write_micandchain, &cbdata);

	if (extrachannels != NULL) {
		for (int i = 0; i < 5; i++)
			lorawan_writer_appendu24(*extrachannels++, packet_write_micandchain,
					&cbdata);
		lorawan_writer_appendu8(0, packet_write_micandchain, &cbdata);
	}

	uint32_t mic = lorawan_crypto_mic_finalise(miccntx);
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

static uint32_t lorawan_packet_readu32(uint8_t* data) {
	uint32_t result = 0;
	for (int i = 3; i >= 0; i--) {
		result = result << 8;
		result |= data[i];
	}

	return result;
}

bool lorawan_packet_verifymic(uint8_t* key, uint8_t* data, size_t len,
		uint32_t* mic, uint32_t* actualmic) {
	uint8_t mhdr = LORAWAN_TYPE(data[0]);
	uint32_t packetmic = 0;
	uint32_t calculatedmic = 0;
	switch (mhdr) {
	case MHDR_MTYPE_JOINREQ:
		packetmic = lorawan_packet_readu32(data + (len - 4));
		calculatedmic = lorawan_crypto_mic_simple(key, data, len - 4);
		break;
	default:
		return false;
	}

	if (mic != NULL)
		*mic = packetmic;
	if (actualmic != NULL)
		*actualmic = calculatedmic;

	return packetmic == calculatedmic;
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
