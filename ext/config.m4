dnl config.m4 for extension pyp (ProtectYourePHP)

PHP_ARG_ENABLE([pyp],
  [whether to enable ProtectYourePHP support],
  [AS_HELP_STRING([--enable-pyp], [Enable ProtectYourePHP native helpers])],
  [no])

if test "$PHP_PYP" != "no"; then
  AC_CHECK_HEADERS([ifaddrs.h netpacket/packet.h net/if_dl.h])
  AC_DEFINE([HAVE_PYP], [1], [Whether ProtectYourePHP support is enabled])
  PHP_NEW_EXTENSION([pyp], [pyp.c], [$ext_shared],, [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])
fi
