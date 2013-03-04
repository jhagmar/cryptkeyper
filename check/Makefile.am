check_PROGRAMS = kdbx_read_test kdbx_gzip_test

kdbx_read_test_SOURCES = kdbx_read_test.c
kdbx_read_test_CPPFLAGS = -I$(top_srcdir)/include -DTESTFILE=\"$(srcdir)/kpdb1.kdbx\"
kdbx_read_test_LDADD = ../libcx9r/libcx9r.la

kdbx_gzip_test_SOURCES = kdbx_gzip_test.c
kdbx_gzip_test_CPPFLAGS = -I$(top_srcdir)/include -DTESTFILE=\"$(srcdir)/kpdb_gzip.kdbx\"
kdbx_gzip_test_LDADD = ../libcx9r/libcx9r.la

dist_noinst_DATA = kpdb1.kdbx kpdb_gzip.kdbx

TESTS = kdbx_read_test kdbx_gzip_test 
