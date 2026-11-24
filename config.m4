dnl $Id: config.m4,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $
dnl config.m4 for extension suhosin

PHP_ARG_ENABLE(suhosin, whether to enable suhosin support,
[  --enable-suhosin        Enable suhosin support])

if test "$PHP_SUHOSIN" != "no"; then
  suhosin_sources="suhosin.c sha256.c memory_limit.c treat_data.c ifilter.c post_handler.c ufilter.c rfc1867_new.c log.c header.c execute.c ex_imp.c session.c aes.c crypt.c pledge.c"
  PHP_NEW_EXTENSION(suhosin, $suhosin_sources, $ext_shared)

  dnl object list for the header dependencies in Makefile.frag
  SUHOSIN_OBJECTS=
  for suhosin_src in $suhosin_sources; do
    SUHOSIN_OBJECTS="$SUHOSIN_OBJECTS $ext_builddir/`echo $suhosin_src | $SED -e 's/\.c$/.lo/'`"
  done
  PHP_SUBST(SUHOSIN_OBJECTS)
  PHP_ADD_MAKEFILE_FRAGMENT
fi

PHP_ARG_ENABLE(suhosin-experimental, whether to enable experimental suhosin features,
[  --enable-suhosin-experimental        Enable experimental suhosin features], no, no)

if test "$PHP_SUHOSIN_EXPERIMENTAL" != "no"; then
  AC_DEFINE(SUHOSIN_EXPERIMENTAL, 1, [Whether to enable experimental suhosin features])
fi
