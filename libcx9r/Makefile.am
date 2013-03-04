lib_LTLIBRARIES = libcx9r.la
libcx9r_la_SOURCES = kdbx.c sha256.h sha256.c aes256.h aes256.c stream.h stream.c util.h util.c base64.c base64.h salsa20.c key_tree.c key_tree.h
libcx9r_la_CPPFLAGS = -I$(top_srcdir)/include $(GCRYPT_CFLAGS) $(EXPAT_CFLAGS)
libcx9r_la_LIBADD = $(GCRYPT_LIBS) $(EXPAT_LIBS)

check_PROGRAMS = buf_file_stream_test base64_test salsa20_test key_tree_test
base64_test_SOURCES = base64_test.c base64.c base64.h
salsa20_test_SOURCES = salsa20_test.c salsa20.c salsa20.h
key_tree_test_SOURCES = key_tree_test.c key_tree.c key_tree.h
buf_file_stream_test_SOURCES = buf_file_stream_test.c stream.c stream.h sha256.c sha256.h util.c util.h aes256.c aes256.h
buf_file_stream_test_CPPFLAGS = -I$(top_srcdir)/include -DTESTFILE=\"$(srcdir)/testfile\" $(GCRYPT_CFLAGS)
buf_file_stream_test_LDADD = $(GCRYPT_LIBS)

TESTS = base64_test salsa20_test key_tree_test buf_file_stream_test
