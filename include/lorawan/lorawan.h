#pragma once

#include <stdint.h>

#define ASCIILEN(n) ((n * 2) + 1)

#define EUILEN		8
#define EUIASCIILEN ((EUILEN * 2) + 1)
#define KEYLEN		16
#define KEYASCIILEN	((KEYLEN * 2) + 1)

#define MHDRLEN		1
#define MICLEN		4
#define APPNONCELEN	3
#define APPNONCEASCIILEN ASCIILEN(APPNONCELEN)
#define DEVNONCELEN 2
#define DEVNONCEASCIILEN	((DEVNONCELEN * 2) + 1)
#define DEVADDRLEN	4
#define DEVADDRASCIILEN ((DEVADDRLEN * 2) + 1)
#define NETIDLEN	3
#define SESSIONKEYLEN	16
#define BLOCKLEN 16

#define MHDR_MTYPE_SHIFT	5
#define MHDR_MTYPE_MASK		0b111
#define MHDR_MTYPE_JOINREQ	0b000
#define MHDR_MTYPE_JOINACK	0b001
#define MHDR_MTYPE_UNCNFUP	0b010
#define MHDR_MTYPE_UNCNFDN	0b011
#define MHDR_MTYPE_CNFUP	0b100
#define MHDR_MTYPE_CNFDN	0b101

#define LORAWAN_TYPE(t) ((t >> MHDR_MTYPE_SHIFT) & MHDR_MTYPE_MASK)

#define LORAWAN_FHDR_FCTRL_FOPTLEN_MASK	0b1111
#define LORAWAN_FHDR_FCTRL_ADR			(1 << 7)
#define LORAWAN_FHDR_FCTRL_ADRACKREQ	(1 << 6)
#define LORAWAN_FHDR_FCTRL_ACK			(1 << 5)
#define LORAWAN_FHDR_FCTRL_FPENDING		(1 << 4)

#define LORAWAN_NOERR			    0
#define LORAWAN_ERR					1
#define LORAWAN_PACKET_UKNWNTYPE	32
#define LORAWAN_CRYPTO_UPDTERR		64
#define LORAWAN_CRYPTO_FNLZERR		65

#define LORAWAN_JOINACK_MAXSZ	33
