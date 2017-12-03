AC_INIT([mod_authz_jwt],[1.0.0rc1],[jonathan.bouzekri@gmail.com],,[https://github.com/jbouzekri/mod_authz_jwt])

AC_CONFIG_SRCDIR([mod_authz_jwt.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

dnl Checks for programs.
AM_PROG_AR
AC_PROG_LIBTOOL

dnl Checks for programs.
AC_PROG_CC

# ----------------
# This section defines the --with-apxs2 option
# and the loading of apache build flags
# ----------------

AC_ARG_WITH(
	[apxs2],
	[--with-apxs2=PATH Full path to the apxs2 executable.],
	[APXS2=${withval}],
)

if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2 option.

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
   AC_MSG_ERROR([Could not find apxs2. Please specify the path to apxs2 using the --with-apxs2=/full/path/to/apxs2 option. The executable may also be named 'apxs'.])
fi

dnl Replace any occurrences of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# Get the APXS configuration environment
APXS_CFLAGS=`${APXS2} -q CFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS2} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS2} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS2} -q LIBEXECDIR 2> /dev/null`
APXS_INCLUDEDIR=`${APXS2} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"
APXS_HTTPD_VERSION=`${APXS2} -q HTTPD_VERSION 2> /dev/null`

# ----------------
# This section defines the --with-apr option
# and the loading of APR build flags
# ----------------

AC_ARG_WITH(
    [apr],
    [--with-apr=PATH full path to the apr-config executable.],
    [APR_CONFIG=${withval}],
)

AC_MSG_CHECKING([for apr-config])

if test "x$APR_CONFIG" = "x"; then
   # The user didn't specify the --with-apr option.

   # Use apxs to determinate the apr-config executable path
   APR_PATH=`${APXS2} -q APR_BINDIR 2> /dev/null`
   APR_CONFIG="${APR_PATH}/apr-1-config"
   if test ! -x "${APR_CONFIG}"; then
     APR_CONFIG="${APR_PATH}/apr-config"
   fi
fi

# Test if APR_CONFIG exists and is an executable.
if test ! -x "${APR_CONFIG}"; then
   # $APR_CONFIG isn't a executable file.
   AC_MSG_ERROR([Could not find apr-config. Please specify the path to apr-config using the --with-apr=/full/path/to/apr-config option.])
fi

AC_MSG_RESULT([${APR_CONFIG}])

APR_INCLUDES=`${APR_CONFIG} --includes 2> /dev/null`
APR_CFLAGS=`${APR_CONFIG} --cflags 2> /dev/null`
APR_LDFLAGS=`${APR_CONFIG} --ldflags 2> /dev/null`
APR_LIBS=`${APR_CONFIG} --libs 2> /dev/null`

# ----------------
# This section defines the --with-jwt option
# and the loading of libjwt build flags
# ----------------

AC_ARG_WITH(
    [jwt],
    [--with-jwt=PATH full path to a checkout of libjwt git repository],
    [JWT_PATH=${withval}],
)

AC_ARG_WITH([jwt],
            [AC_HELP_STRING([--with-jwt=PATH],
                            [libjwt library path])],
            [JWT_PATH="$withval"],
            [with_jwt=yes])

if test "x$JWT_PATH" = "x"; then
   # The user didn't specify the --with-jwt option.

   # Check that the JWT module is installed in a ld available path
   PKG_CHECK_MODULES(JWT, libjwt)
else
   # The user specify the --with-jwt option

   AC_MSG_CHECKING([for JWT])

   # Check that it is really a checkout of the libjwt repository and that is already compiled
   if test ! -d "${JWT_PATH}" ; then
       AC_MSG_ERROR(invalid path "${JWT_PATH}")
   fi
   if test ! -f "${JWT_PATH}/include/jwt.h"  && test ! -f "${JWT_PATH}/libjwt/.libs/libjwt.so"; then
       AC_MSG_ERROR(libjwt not compiled in path "${JWT_PATH}")
   fi

   JWT_CFLAGS="-I${JWT_PATH}/include"
   JWT_LDFLAGS="-L${JWT_PATH}/libjwt/.libs -Wl,-rpath=${JWT_PATH}/libjwt/.libs"
   JWT_LIBS="-ljwt"

   AC_MSG_RESULT(yes)
fi

# ----------------
# This section handles the configuration
# of the Makefile
# ----------------

# Check that a2enmod program is available
#AC_PATH_PROG(A2ENMOD, a2enmod2, no)

# Apache module install and libraries directories
if test -z "$prefix" || test "x$prefix" = "x" || test "$prefix" = NONE ; then
    APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
else
    APACHE_MODULEDIR="${prefix}"
fi
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES}"

# Build option for mod_authz_jwt
AUTHZJWT_CFLAGS="${APACHE_INCLUDES} ${APXS_CFLAGS} ${APR_CFLAGS} ${JWT_CFLAGS}"
AUTHZJWT_LDFLAGS="${APXS_LDFLAGS} ${APXS_LIBS} ${APR_LDFLAGS} ${APR_LIBS} ${JWT_LDFLAGS} ${JWT_LIBS}"

dnl Replace all @VARIABLE@ references
AC_SUBST(APACHE_MODULEDIR)
AC_SUBST(AUTHZJWT_CFLAGS)
AC_SUBST(AUTHZJWT_LDFLAGS)

dnl Create Makefile from Makefile.in
AC_CONFIG_FILES([
    Makefile
    authz_jwt.load
])

AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

    Version:        ${PACKAGE_VERSION}
    Host type:      ${host}
    Install:        ${APACHE_MODULEDIR}
    apxs:           ${APXS2}
    apr-config:     ${APR_CONFIG}
    httpd:          ${APXS_HTTPD_VERSION}
    C compiler:     ${CC}
    CFLAGS:         ${AUTHZJWT_CFLAGS}
    LDFLAGS:        ${AUTHZJWT_LDFLAGS}
])