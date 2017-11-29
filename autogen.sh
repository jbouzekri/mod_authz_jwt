#!/bin/sh

echo "Cleanup"
rm -rf .libs autom4te*.cache scripts aclocal.m4 configure config.log config.status config.guess config.sub .deps stamp-h1 depcomp install-sh ltmain.sh missing libtool config.h config.h.in config.h.in~ m4 ar-lib compile
rm -rf *.o *.la *.lo *.slo Makefile.in Makefile

if [ "$1" = "clean" ] ; then
    exit
fi

echo "autoreconf"
autoreconf -vif