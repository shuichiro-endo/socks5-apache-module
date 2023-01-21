mod_socks5.la: mod_socks5.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_socks5.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_socks5.la
