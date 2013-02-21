#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([cryptkeyper], [0.0.0], [jonas.hagmar@gmail.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

# Checks for libraries.
#AM_PATH_LIBGCRYPT
AX_LIB_GCRYPT([yes])
AX_CHECK_ZLIB
AX_LIB_EXPAT([2.0.0])

# Checks for header files.
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AX_C_BIGENDIAN_CROSS

# Checks for library functions.
#AC_SEARCH_LIBS([fopen], [libc])
#AC_SEARCH_LIBS([fread], [libc])
#AC_SEARCH_LIBS([fclose], [libc])
#AC_SEARCH_LIBS([memcmp], [libc])
#AC_SEARCH_LIBS([malloc], [libc])
#AC_SEARCH_LIBS([free], [libc])
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 libcx9r/Makefile
		 include/Makefile
		 check/Makefile
		 doc/Makefile])
AC_OUTPUT
