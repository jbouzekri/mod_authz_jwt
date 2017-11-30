# Miscellaneous

This folder contains some miscellaneous scripts to test the [libjwt](https://github.com/benmcollins/libjwt) library

## Prerequisites

You need to have the [libjwt](https://github.com/benmcollins/libjwt) installed in your `LD_LIBRARY_PATH`.

If you are on Debian, the easiest is to use the library PPA :

```
sudo add-apt-repository ppa:ben-collins/libjwt
sudo apt-get update
sudo apt-get install libjwt0 libjwt-dev
```

## jwt_decode

A simple script that decodes a jwt token generated using [PyJWT](https://github.com/jpadilla/pyjwt).

*Note : this token comes from a [Flask-Restful](https://flask-restful.readthedocs.io/en/latest/) API with [Flask-JWT](https://pythonhosted.org/Flask-JWT/). That's why you have an identity key used to identify the authenticated user id in this API*

```
gcc -o jwt_decode jwt_decode.c -ljwt
./jwt_decode
```