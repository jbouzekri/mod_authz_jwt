ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_authz_jwt.la

mod_authz_jwt_la_SOURCES = mod_authz_jwt.c

mod_authz_jwt_la_CFLAGS = @AUTHZJWT_CFLAGS@
mod_authz_jwt_la_LDFLAGS = -avoid-version -module @AUTHZJWT_LDFLAGS@

install-data-hook:
	@echo 'Cleaning unneeded files for apache modules'
	rm @APACHE_MODULEDIR@/mod_authz_jwt.la
	rm @APACHE_MODULEDIR@/mod_authz_jwt.a
	@echo '----------------------------------------------------------------------'
	@echo 'mod_authz_jwt.so file installed in:'
	@echo '    @APACHE_MODULEDIR@'
	@echo ''
	@echo 'authz_jwt.load file available. Copy it to your apache module'
	@echo 'configuration folder. Then restart apache.'
	@echo '    apache2ctl restart'
	@echo ''
	@echo 'For example on a Debian based installation:'
	@echo '    cp authz_jwt.load /etc/apache2/mods-available/'
	@echo '    a2enmod authz_jwt'
	@echo '    apache2ctl restart'
	@echo ''
	@echo 'To protect an url with a valid JWT token, add at least this'
	@echo 'configuration in a Directory or Location settings :'
	@echo '    AuthJwtKey yourjwtsecretkey'
	@echo '    Require valid-jwt-token'
	@echo '----------------------------------------------------------------------'