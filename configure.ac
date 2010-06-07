# init
AC_INIT(src/main.c)
# config header
AM_CONFIG_HEADER(src/config.h)
# name and version
AM_INIT_AUTOMAKE(cryptutil,0.0.1)
# checks for compiler
AC_PROG_CC
# checks for libraries
AC_CHECK_LIB([parted],[main])
# checks for header files
AC_CHECK_HEADERS([fcntl.h mntent.h stdlib.h string.h unistd.h])
# checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
# checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_GETMNTENT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_CHECK_FUNCS([getmntent mkdir realpath rmdir strerror strrchr strstr])
# make "make install"
AC_PROG_INSTALL
# generate makefile
AC_OUTPUT(Makefile src/Makefile)
