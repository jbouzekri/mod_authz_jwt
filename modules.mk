mod_authz_jwt.la: mod_authz_jwt.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_jwt.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authz_jwt.la
