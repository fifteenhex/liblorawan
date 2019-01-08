#include <string.h>

#include "include/lorawan/lorawan.h"
#include "include/lorawan/crypto.h"
#include "include/lorawan/packet.h"

#define COPYANDINC(dst, src)	memcpy(dst, src, sizeof(*dst));\
									src += sizeof(*dst)

int packet_pack(struct packet_unpacked* unpacked, uint8_t* nwksk,
		uint8_t* appsk) {
	int ret = LORAWAN_NOERR;
	size_t pktlen;
	uint8_t* pkt = NULL;
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

	out:
	//if (pkt != NULL)
	//	g_free(pkt);

	return ret;
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
