AC_INIT([mod_authz_jwt],[1.0.0rc1],[jonathan.bouzekri@gmail.com],,[https://github.com/jbouzekri/mod_authz_jwt])

AC_CONFIG_SRCDIR([mod_authz_jwt.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AM_PROG_AR
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# This section defines the --with-apxs2 option.
AC_ARG_WITH(
	[apxs2],
	[--with-apxs2=PATH Full path to the apxs2 executable.],
	[APXS2=${withval}],
)

if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2-option.

   # Search for apxs2 in the specified directories
   AC_PATH_PROG(APXS2, apxs2,, /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

   if test "x$APXS2" = "x"; then
      # Didn't find apxs2 in any of the specified directories.
      # Search for apxs instead.
      AC_PATH_PROG(APXS2, apxs,, /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
   fi

fi

# Test if $APXS2 exists and is an executable.
if test ! -x "$APXS2"; then
   # $APXS2 isn't a executable file.
   AC_MSG_ERROR([
    Could not find apxs2. Please specify the path to apxs2
    using the --with-apxs2=/full/path/to/apxs2 option.
    The executable may also be named 'apxs'.
   ])
fi

# Replace any occurrences of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# Use environment varilable APXS2_OPTS to pass params to APXS2 command
AC_ARG_VAR(APXS2_OPTS, [Additional command line options to pass to apxs2.])

# Get the APXS configuration environment
APXS_CFLAGS=`${APXS2} -q CFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS2} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS2} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS2} -q LIBEXECDIR 2> /dev/null`
APXS_INCLUDEDIR=`${APXS2} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"

HTTPD_VERSION=`${APXS2} -q HTTPD_VERSION 2> /dev/null`

# Checks for apr.
AC_ARG_WITH([apr],
            [AC_HELP_STRING([--with-apr=PATH],
                            [apr config path [default=yes]])],
            [APR_CONFIG="$withval"],
            [with_apr=yes])

AC_MSG_CHECKING([whether apr])
AS_IF([test "x$with_apr" != "xno"],
      [if test ! -x "${APR_CONFIG}" -o -z "${APR_CONFIG}"; then
         APR_PATH=`${APXS2} -q APR_BINDIR 2> /dev/null`
         APR_CONFIG="${APR_PATH}/apr-1-config"
         if test ! -x "${APR_CONFIG}"; then
           APR_CONFIG="${APR_PATH}/apr-config"
         fi
       fi
       APR_INCLUDES=`${APR_CONFIG} --includes 2> /dev/null`
       APR_CFLAGS=`${APR_CONFIG} --cflags 2> /dev/null`
       APR_LDFLAGS=`${APR_CONFIG} --ldflags 2> /dev/null`
       APR_LIBS=`${APR_CONFIG} --libs 2> /dev/null`
       AC_MSG_RESULT(yes)],
      [AC_MSG_ERROR(apr not found)])


# Checks for jwt
AC_ARG_WITH([jwt],
            [AC_HELP_STRING([--with-jwt=PATH],
                            [libjwt library path])],
            [JWT_PATH="$withval"],
            [with_jwt=yes])

AS_IF([test "x$with_jwt" = "xyes"],
      [PKG_CHECK_MODULES(JWT, libjwt)],
      [test "x$with_jwt" != "xno"],
      [AC_MSG_CHECKING([whether jwt])
       if test ! -d "${JWT_PATH}" && test ! -f "${JWT_PATH}/include/jwt.h"  && test ! -f "${JWT_PATH}/libjwt/.libs/libjwt.so"; then
         AC_MSG_ERROR(invalid libjwt path "${JWT_PATH}")
       fi
       JWT_CFLAGS="-I${JWT_PATH}/include"
       JWT_LDFLAGS="-L${JWT_PATH}/libjwt/.libs"
       JWT_LIBS="-ljwt"
       AC_MSG_RESULT(yes)],
      [AC_MSG_ERROR(no libjwt found)]
      )

# Check that a2enmod program is available
#AC_PATH_PROG(A2ENMOD, a2enmod2, no)

# Apache libraries.
APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES}"

APACHE_CFLAGS="${APXS_CFLAGS} ${APR_CFLAGS} ${JWT_CFLAGS} ${APACHE_INCLUDES}"
APACHE_LDFLAGS="${APXS_LDFLAGS} ${APR_LDFLAGS} ${JWT_LDFLAGS}"
APACHE_LIBS="${APXS_LIBS} ${APR_LIBS} ${JWT_LIBS}"

AC_SUBST(APACHE_MODULEDIR)
AC_SUBST(APACHE_INCLUDES)
AC_SUBST(APACHE_CFLAGS)
AC_SUBST(APACHE_LDFLAGS)
AC_SUBST(APACHE_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])

AC_OUTPUT

AC_MSG_NOTICE([
Summary:
cflags:  ${APACHE_CFLAGS}
ldflags: ${APACHE_LDFLAGS}
libs:    ${APACHE_LIBS}
])