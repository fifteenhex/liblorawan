from libc.stdint cimport uint64_t, uint16_t, uint8_t
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AsString
import sys

cdef extern from "include/lorawan/writer.h":
	ctypedef int (*lorawan_writer)(uint8_t* data, size_t len, void* userdata)

cdef extern from "include/lorawan/packet.h":
	int packet_build_joinreq(uint8_t* key, uint64_t appeui, uint64_t deveui, uint16_t devnonce, lorawan_writer cb, void* userdata);

cdef extern from "include/lorawan/crypto.h":
	int lorawan_crypto_decrypt_joinack(const unsigned char* key, void* data, size_t datalen, lorawan_writer writer, void* userdata);

cdef int __bytearray_writer(uint8_t* data, size_t len, void* userdata):
	asbytes = PyBytes_FromStringAndSize(<char*>data,len)
	ba=<object>userdata
	ba += asbytes
	return 0

def build_joinreq(bytes key, bytes appeui, bytes deveui, bytes devnonce) -> bytearray:
	assert len(key) is 16
	assert len(appeui) is 8
	assert len(deveui) is 8
	assert len(devnonce) is 2
	
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
	
	native_devnonce = bytearray(devnonce)
	native_devnonce.reverse()
	devnonce = bytes(native_devnonce)

	c_key = <uint8_t*> PyBytes_AsString(key)
	c_appeui = (<uint64_t*> PyBytes_AsString(appeui))[0]
	c_deveui = (<uint64_t*> PyBytes_AsString(deveui))[0]
	c_devnonce = (<uint16_t*> PyBytes_AsString(devnonce))[0]
	
	ba = bytearray()
	packet_build_joinreq(c_key, c_appeui, c_deveui, c_devnonce, __bytearray_writer, <void*> ba)
	return ba

def decrypt_joinack(bytes key, bytes packet) -> bytearray:
	assert len(key) is 16
	assert (len(packet) - 1) % 16 == 0

	c_key = <uint8_t*> PyBytes_AsString(key)
	c_encryptedpart = <uint8_t*> PyBytes_AsString(packet[1:])

	ba = bytearray()
	ba += packet[1:1]
	lorawan_crypto_decrypt_joinack(c_key, c_encryptedpart, len(packet)-1, __bytearray_writer, <void*> ba)
	return ba
