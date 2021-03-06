from libc.stdint cimport uint64_t, uint32_t, uint16_t, uint8_t
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AsString
import sys

cdef extern from "stdbool.h":
	ctypedef bint bool

cdef extern from "include/lorawan/writer.h":
	ctypedef int (*lorawan_writer)(uint8_t* data, size_t len, void* userdata)

cdef extern from "include/lorawan/packet.h":
	int lorawan_packet_build_joinreq(uint8_t* key, uint64_t appeui, uint64_t deveui, uint16_t devnonce, lorawan_writer cb, void* userdata);
	int lorawan_packet_build_data(uint8_t type, uint32_t devaddr, bool adr, bool adrackreq, bool ack, bool fpending, uint32_t framecounter, uint8_t port, const uint8_t* payload, size_t payloadlen, uint8_t* nwksk, uint8_t* appsk, lorawan_writer cb, void* userdata);

cdef extern from "include/lorawan/crypto.h":
	int lorawan_crypto_decrypt_joinack(const unsigned char* key, void* data, size_t datalen, lorawan_writer writer, void* userdata);
	uint32_t lorawan_crypto_mic_simple(const void* key, const void* data, size_t datalen);
	void lorawan_crypto_calculatesessionkeys(const uint8_t* key, uint32_t appnonce, uint32_t netid, uint16_t devnonce, uint8_t* networkkey, uint8_t* appkey)

cdef int __bytearray_writer(uint8_t* data, size_t len, void* userdata):
	asbytes = PyBytes_FromStringAndSize(<char*>data,len)
	ba=<object>userdata
	ba += asbytes
	return 0

def build_joinreq(bytes key, bytes appeui, bytes deveui, int devnonce) -> bytearray:
	assert len(key) is 16
	assert len(appeui) is 8
	assert len(deveui) is 8
	
	# on a little endian machine we'll need to flip the appeui
	# deveui and devnonce around. Maybe this isn't needed
	# if the interface is better? Dunno.
	#if sys.byteorder is 'little':
	native_appeui = bytearray(appeui)
	native_appeui.reverse()
	appeui = bytes(native_appeui)
	 
	native_deveui = bytearray(deveui)
	native_deveui.reverse()
	deveui = bytes(native_deveui)

	c_key = <uint8_t*> PyBytes_AsString(key)
	c_appeui = (<uint64_t*> PyBytes_AsString(appeui))[0]
	c_deveui = (<uint64_t*> PyBytes_AsString(deveui))[0]
	
	ba = bytearray()
	lorawan_packet_build_joinreq(c_key, c_appeui, c_deveui, devnonce, __bytearray_writer, <void*> ba)
	return ba

def decrypt_joinack(bytes key, bytes packet) -> bytearray:
	assert len(key) is 16
	assert (len(packet) - 1) % 16 == 0

	c_key = <uint8_t*> PyBytes_AsString(key)
	encryptedpart = packet[1:]
	c_encryptedpart = <uint8_t*> PyBytes_AsString(encryptedpart)

	ba = bytearray()
	ba += packet[0:1]
	lorawan_crypto_decrypt_joinack(c_key, c_encryptedpart, len(encryptedpart), __bytearray_writer, <void*> ba)
	return ba
	
def calculate_mic(bytes key, bytes data) -> int:
	assert len(key) is 16
	c_key = <uint8_t*> PyBytes_AsString(key)
	c_data = <uint8_t*> PyBytes_AsString(data)
	mic = lorawan_crypto_mic_simple(c_key, c_data, len(data))
	return mic

def calculate_sessionkeys(bytes key, int appnonce, int netid, int devnonce) -> bytes:
	c_key = <uint8_t*> PyBytes_AsString(key)
	cdef uint8_t networkkey[16]
	cdef uint8_t appkey[16]
	lorawan_crypto_calculatesessionkeys(c_key, appnonce, netid, devnonce, networkkey, appkey)
	ntwkkey_asbytes = PyBytes_FromStringAndSize(<char*>networkkey,16)
	appkey_asbytes = PyBytes_FromStringAndSize(<char*>appkey,16)
	ba= bytearray()
	ba += ntwkkey_asbytes
	ba += appkey_asbytes
	return bytes(ba)

def build_data(int type, long devaddr, int framecounter, int port, bytes payload, bytes nwksk, bytes appsk, bool adr=False, adrackreq=False, bool ack=False, fpending=False) -> bytes:
	assert nwksk is not None and len(nwksk) is 16
	assert appsk is not None and len(appsk) is 16
	
	cdef uint8_t* c_payload = NULL
	payload_len = 0
	if payload is not None:
		c_payload = <uint8_t*> PyBytes_AsString(payload)
		payload_len = len(payload)
	
	c_nwksk = <uint8_t*> PyBytes_AsString(nwksk)
	c_appsk = <uint8_t*> PyBytes_AsString(appsk)
	ba = bytearray()
	ret = lorawan_packet_build_data(type, devaddr, adr, adrackreq, ack, fpending, framecounter, port, c_payload, payload_len, c_nwksk, c_appsk, __bytearray_writer, <void*> ba)
	if ret is 0:
		return bytes(ba)
	else:
		return None
