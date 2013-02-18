lib_LTLIBRARIES = libcx9r.la
libcx9r_la_SOURCES = kdbx.c sha256.h sha256.c aes256.h aes256.c stream.c util.h util.c base64.c base64.h salsa20.c
libcx9r_la_CPPFLAGS = -I$(top_srcdir)/include $(GCRYPT_CFLAGS)
libcx9r_la_LIBADD = $(GCRYPT_LIBS)

check_PROGRAMS = base64_test
base64_test_SOURCES = base64_test.c base64.c base64.h

TESTS = base64_test

