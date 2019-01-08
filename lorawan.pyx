from libc.stdint cimport uint64_t, uint16_t, uint8_t
from cpython.bytes cimport PyBytes_FromStringAndSize

cdef extern from "include/lorawan/writer.h":
	ctypedef int (*lorawan_writer)(uint8_t* data, size_t len, void* userdata)

cdef extern from "include/lorawan/packet.h":
	int packet_build_joinreq(uint8_t* key, uint64_t appeui, uint64_t deveui, uint16_t devnonce, lorawan_writer cb, void* userdata);

cdef int __bytearray_writer(uint8_t* data, size_t len, void* userdata):
	asbytes = PyBytes_FromStringAndSize(<char*>data,len)
	ba=<object>userdata
	ba += asbytes
	return 0

def builder_joinreq() -> bytearray:
	ba = bytearray()
	packet_build_joinreq(NULL,0,0,0, __bytearray_writer, <void*> ba)
	return ba