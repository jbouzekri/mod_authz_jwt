# mod_authz_jwt

A apache 2.4 module to verify that a valid JWT token has been passed

Install libjwt

```
sudo apt-get install libjansson-dev automake
git clone git@github.com:benmcollins/libjwt.git
cd libjwt
autoreconf -i
./configure
make all
```

Then build and install this module :

```
$ apxs -c -I $PWD/libjwt/include -L $PWD/libjwt/libjwt/.libs -l jwt mod_authz_jwt.c
$ sudo cp .libs/mod_authz_jwt.so /usr/lib/apache2/modules/
```

```
$ cat /etc/apache2/mods-enabled/authz_jwt.load
LoadModule authz_jwt_module   /usr/lib/apache2/modules/mod_authz_jwt.so
$ apache2ctl restart
```