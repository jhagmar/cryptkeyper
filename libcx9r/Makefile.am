lib_LTLIBRARIES = libcx9r.la
libcx9r_la_SOURCES = kdbx.c sha256.h sha256.c aes256.h aes256.c stream.c util.h util.c base64.c base64.h salsa20.c key_tree.c key_tree.h
libcx9r_la_CPPFLAGS = -I$(top_srcdir)/include $(GCRYPT_CFLAGS)
libcx9r_la_LIBADD = $(GCRYPT_LIBS)

check_PROGRAMS = base64_test salsa20_test key_tree_test
base64_test_SOURCES = base64_test.c base64.c base64.h
salsa20_test_SOURCES = salsa20_test.c salsa20.c salsa20.h
key_tree_test_SOURCES = key_tree_test.c key_tree.c key_tree.h

TESTS = base64_test salsa20_test key_tree_test
