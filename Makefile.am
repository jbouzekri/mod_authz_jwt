ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_authz_jwt.la

mod_authz_jwt_la_SOURCES = mod_authz_jwt.c

mod_authz_jwt_la_CFLAGS = @APACHE_CFLAGS@
mod_authz_jwt_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@ @APACHE_LIBS@

#install-exec-local: mod_authz_jwt.la
#	if test ! -d ${DESTDIR}${APXS_LIBEXECDIR}; then mkdir -p ${DESTDIR}${APXS_LIBEXECDIR}; fi
#	@APXS2@ -i -S LIBEXECDIR=${DESTDIR}${APXS_LIBEXECDIR} mod_authz_jwt.la