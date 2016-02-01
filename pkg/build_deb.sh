#!/bin/bash

_exit() {
	echo "[E] bye."
	exit 1
}

yn_or_exit() {
	echo -n "[?] OK? [y] "
	read yn
	if [ "$yn" != "" -a "$yn" != "y" ]; then
		_exit
	fi
}

##

echo "[*] checking prerequisites..."
for i in phpize make install fakeroot php-config dpkg-deb dpkg-architecture; do
	if [ "`which $i`" == "" ]; then
		echo "[E] please install '$i' and try again."
		_exit
	fi
done

##

HERE=`(cd $(dirname $0); pwd)`
SUHOSIN=$HERE/..
ROOT=$HERE/tmp
PKGDIR=$HERE
PHP_EX=`php-config --extension-dir`
eval `dpkg-architecture -l`
VERSION=${SUHOSIN_VERSION:-$1}

if [ "$VERSION" == "" ]; then
	echo "[E] please set SUHOSIN_VERSION, e.g. $0 0.9.36-1~dev1"
	_exit
fi

echo "[*] -----------------------------------------------------------"
echo "[+]         suhosin dir: $SUHOSIN"
echo "[+]             tmp dir: $ROOT"
echo "[+]   PHP extension dir: $PHP_EX"
echo "[+]        architecture: $DEB_HOST_ARCH"
echo "[+] suhosin deb version: $VERSION"
echo "[+]      pkg output dir: $PKGDIR"
yn_or_exit

if [ ! -f "$SUHOSIN/modules/suhosin.so" ]; then
	echo "[+] Cannot find suhosin.so. I will try to build it."
	yn_or_exit
	
	eval `dpkg-buildflags --export=sh`
	
	if [ ! -f "$SUHOSIN/configure" ]; then
		echo "[*] phpize"
		cd $SUHOSIN
		phpize || _exit
	fi
	
	if [ ! -f "$SUHOSIN/Makefile" ]; then
		echo "[*] configure"
		cd $SUHOSIN
		./configure --enable-suhosin-experimental
	fi
	
	echo "[*] make"
	make clean
	make -C $SUHOSIN || _exit
fi

##

echo "[*] deb"

if [ -d "$ROOT" ]; then
	echo "[+] tmp dir $ROOT already exists. Delete?"
	yn_or_exit
	rm -rf $ROOT
fi

##

mkdir -p $ROOT/DEBIAN
#echo "9" >$ROOT/DEBIAN/compat
cat >$ROOT/DEBIAN/control <<EOF
Package: php5-suhosin-extension
Section: php
Priority: extra
Maintainer: Ben Fuhrmannek <ben@sektioneins.de>
Homepage: http://www.suhosin.org/
Conflicts: php5-suhosin
Depends: php5-common
Description: advanced protection system for PHP5
 This package provides a PHP hardening module.
 .
 Suhosin is an advanced protection system for PHP installations. It was
 designed to protect servers and users from known and unknown flaws in PHP
 applications and the PHP core. Suhosin comes in two independent parts, that
 can be used separately or in combination. The first part is a small patch
 against the PHP core, that implements a few low-level protections against
 bufferoverflows or format string vulnerabilities and the second part is a
 powerful PHP extension that implements all the other protections.
 .
 This Package provides the suhosin extension only.
EOF

echo "Architecture: $DEB_HOST_ARCH" >>$ROOT/DEBIAN/control
echo "Version: $VERSION" >>$ROOT/DEBIAN/control

echo "/etc/php5/mods-available/suhosin.ini" >$ROOT/DEBIAN/conffiles

install -d -g 0 -o 0 $ROOT$PHP_EX
install -g 0 -o 0 -m 644 $SUHOSIN/modules/suhosin.so $ROOT$PHP_EX
install -d -g 0 -o 0 $ROOT/usr/share/doc/php5-suhosin-extension
install -g 0 -o 0 -m 644 $SUHOSIN/suhosin.ini $ROOT/usr/share/doc/php5-suhosin-extension/suhosin.ini.example
install -d -g 0 -o 0 $ROOT/etc/php5/mods-available
( echo '; priority=70' ; sed -e 's/^;extension=/extension=/' $SUHOSIN/suhosin.ini ) >$ROOT/etc/php5/mods-available/suhosin.ini
chown root:root $ROOT/etc/php5/mods-available/suhosin.ini

fakeroot dpkg-deb -b $ROOT $PKGDIR

echo "[*] done."
