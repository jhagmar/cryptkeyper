check_PROGRAMS = kdbx_read_test buf_file_stream_test

kdbx_read_test_SOURCES = kdbx_read_test.c
kdbx_read_test_CPPFLAGS = -I$(top_srcdir)/include -DTESTFILE=\"$(srcdir)/kpdb1.kdbx\"
kdbx_read_test_LDADD = ../libcx9r/libcx9r.la

buf_file_stream_test_SOURCES = buf_file_stream_test.c
buf_file_stream_test_CPPFLAGS = -I$(top_srcdir)/include -DTESTFILE=\"$(srcdir)/testfile\"
buf_file_stream_test_LDADD = ../libcx9r/libcx9r.la

dist_noinst_DATA = kpdb1.kdbx

TESTS = kdbx_read_test buf_file_stream_test
