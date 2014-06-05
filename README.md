suhosin
=======

Suhosin Extension

for generate deb file enter command

sudo apt-get -y install php5-dev git build-essential debhelper cdbs lintian build-essential fakeroot devscripts pbuilder dh-make debootstrap
git clone https://github.com/stefanesser/suhosin.git php5-suhosin-0.9.36
cd php5-suhosin-0.9.36
rm -rf .git .gitignore
dh_make --createorig -e your@email
rm -f debian/rules
mv rules debian/
# for publich on launchpad
debuild -S -sa

dput ppa:username/ppa php5-suhosin_0.9.36-1_source.changes
# for create deb file
debuild
