# docker-sign-verify

## Overview

A utility that can be used to create and verify embedded signatures in docker images, and verify the integrity of image metadata and layers.

The goal of this utility is to operate directly on:

* Docker Registries (v2)
* Docker Repositories (devicemapper, overlay2, aufs)
* Docker archives (from docker-save)

## Features

* Verifies and signs files in place; no need to replicate images using docker-cli.
* Extensible signing technologies; built-in support for GnuPG and PKI.
* Integrates with the docker credentials store.

## Compatibility

* Tested with python 3.8

## Installation
### From [pypi.org](https://pypi.org/project/docker-sign-verify/)

```
$ pip install docker_sign_verify
```

### From source code

```bash
$ git clone https://github.com/crashvb/docker-sign-verify
$ cd docker-sign-verify
$ virtualenv env
$ source env/bin/activate
$ python -m pip install --editable .[dev]
```

## Usage
### Signing and verifying an image

Using master key with id `7DDD762AFCDF1E55` and sukey with id `9DD1BB948581B0AD`:

```bash
$ gpg --keyid-format LONG --list-keys 7DDD762AFCDF1E55
pub   rsa4096/7DDD762AFCDF1E55 2017-11-30 [SC] [expires: 2027-11-28]
uid                 [ultimate] Richard Davis <crashvb>
sub   rsa4096/9DD1BB948581B0AD 2017-11-30 [S] [expires: 2027-11-28]
```

Resolve the tag `crashvb/base:ubuntu` in a remote registry `registry:5000`, verify all layers, and sign the digest of the
canonicalized configuration. Then, upload a new manifest containing the embedded signatures, and assign it the tag
`crashvb/base:ubuntu_signed`.


```bash
$ docker-sign --debug registry --keyid="7DDD762AFCDF1E55" registry:5000/crashvb/base:ubuntu registry:5000/crashvb/base:ubuntu_signed
Keypass []:
INFO:root:Signing: registry:5000/crashvb/base:ubuntu ...
INFO:root:Verifying Integrity: registry:5000/crashvb/base:ubuntu ...
DEBUG:root:    config digest: sha256:8ff76ab7ecbe0...424bf93cacad083c0
DEBUG:root:    manifest layers:
                        sha256:3b37166ec6145...4e6a6e7580cdeff8e
                        sha256:504facff238fd...ddc52d31448a044bd
                        sha256:ebbcacd28e101...73bf796e12b1bb449
                        sha256:c7fb3351ecad2...042086fe72c902b8a
                        sha256:2e3debadcbf7e...eca27cb4d809d56c2
                        sha256:a5396a146776f...4e30f97ed2e9891a4
                        sha256:6389d93ef5c7f...243609c6f41637e84
                        sha256:e05442215521c...fbdadc15c5c80294f
                        sha256:f4ed07aa21a9b...f1fd5a4095bf575c9
                        sha256:e41e7b47a71d3...4611b5ed003208f81
                        sha256:ae19c1f4b6b19...b28fef2632aca9064
DEBUG:root:    image layers:
                        sha256:8823818c47486...45be9ba0eb149a643
                        sha256:19d043c86cbcb...da1e8fc6ce1e43d7f
                        sha256:883eafdbe580e...50cad1875e13e3915
                        sha256:4775b2f378bb7...91719367c739ef25a
                        sha256:75b79e19929ce...1ee48b949261770cf
                        sha256:440c82316bee2...ed8d2c3f168299db8
                        sha256:0538f6ef1ac4c...4cb5a61b9bd530929
                        sha256:090cbbe4fbc62...25f7322fb5cd1d619
                        sha256:5b42cc22f7bd7...4492f3790f05fccbc
                        sha256:ffd252d089fe6...b41e7336a18e12c8a
                        sha256:22681af0cc030...ca77af16b6bfeb204
INFO:root:Integrity check passed.
DEBUG:root:    Signature:
-----BEGIN PGP SIGNATURE-----

iQIcBAABCgAGBQJcW2I9AAoJEJ3Ru5SFgbCtfW0QAJO4WCS/0hPwby3RpIYxSZ74
dcr7lRccsH7afdEuFXp5SlxXBL8gXyfEAcmUcuwzhapGdBPntWXqf10R3tq9Bx0j
36AOwZGt+vSCGdvOz6MEyCgS/JBXXGAUt3L0ciB4dCh/Un2ANSqQ1g+vT2zhHoL5
HggzDTaddawU8sSGhIj/fR62+ari5xWIXs2Vn3+wTjrdiQ6G3W2cb64LWTCYo2sH
qenDO4Z3AkdzRMT10Z4IqkU2XjHQiqIJhdcdJMnF+JZU8pbzmKDyXLE5JOt8Dx39
R2G4AUNXA9vQClYBShAUSTSB2nMRd2fX2GWd/jKgn0mvLa3a+V27VmYW/jQGRWHW
qlJsh0WUBeVQjLGpf+zqknhAXnNmm5ZIvCYqPVJ3PAR6BGi7luzk9s2wBgzlDbED
JCaFka6U1b/YAAc+PTs6Am4N0bGS1p9r7GWb+i7PFWTwH/H5D1MDXDgDNyjE52Qh
DyXgcaJBnQbu2T6BbzYY2WSyvjPWVOkwQGb2lpBKrO7Y1w7T7VMlTVloI+hPWfSs
5VxmfyFNJFHq5Iqo1N76W1/mSDPxv6qF3NOxvK+rMsoqqGJ7/BR8RB4jueeXTgLf
Yr0rnXDsuKbNmh88x/GPg+xbf3m2nVv9kB0F5vhb9J756rlwb1A8+RDVDRs5ICLF
m7KvRvDb7+zZvnur5lTu
=voGn
-----END PGP SIGNATURE-----
DEBUG:root:    config digest (signed): sha256:d9e31c5898fe25bb7b3ac86f8570b8961d5d878aace796920a9da3f8cd8251cb
INFO:root:Created new image: registry:5000/crashvb/base:ubuntu_signed
```

Resolve the tag `crashvb/base:ubuntu_signed` in a remote registry `registry:5000`, verify all layers and embedded
signatures.

```bash
$ docker-verify --debug registry registry:5000/crashvb/base:ubuntu_signed
INFO:root:Verifying Integrity: registry:5000/crashvb/base:ubuntu_signed ...
DEBUG:root:    config digest: sha256:d9e31c5898fe2...20a9da3f8cd8251cb
DEBUG:root:    manifest layers:
                        sha256:3b37166ec6145...4e6a6e7580cdeff8e
                        sha256:504facff238fd...ddc52d31448a044bd
                        sha256:ebbcacd28e101...73bf796e12b1bb449
                        sha256:c7fb3351ecad2...042086fe72c902b8a
                        sha256:2e3debadcbf7e...eca27cb4d809d56c2
                        sha256:a5396a146776f...4e30f97ed2e9891a4
                        sha256:6389d93ef5c7f...243609c6f41637e84
                        sha256:e05442215521c...fbdadc15c5c80294f
                        sha256:f4ed07aa21a9b...f1fd5a4095bf575c9
                        sha256:e41e7b47a71d3...4611b5ed003208f81
                        sha256:ae19c1f4b6b19...b28fef2632aca9064
DEBUG:root:    image layers:
                        sha256:8823818c47486...45be9ba0eb149a643
                        sha256:19d043c86cbcb...da1e8fc6ce1e43d7f
                        sha256:883eafdbe580e...50cad1875e13e3915
                        sha256:4775b2f378bb7...91719367c739ef25a
                        sha256:75b79e19929ce...1ee48b949261770cf
                        sha256:440c82316bee2...ed8d2c3f168299db8
                        sha256:0538f6ef1ac4c...4cb5a61b9bd530929
                        sha256:090cbbe4fbc62...25f7322fb5cd1d619
                        sha256:5b42cc22f7bd7...4492f3790f05fccbc
                        sha256:ffd252d089fe6...b41e7336a18e12c8a
                        sha256:22681af0cc030...ca77af16b6bfeb204
INFO:root:Integrity check passed.
INFO:root:Verifying Signature(s): registry:5000/crashvb/base:ubuntu_signed ...
DEBUG:root:    config digest (signed): sha256:d9e31c5898fe2...20a9da3f8cd8251cb
DEBUG:root:    config digest (unsigned): sha256:8ff76ab7ecbe0...424bf93cacad083c0
DEBUG:root:    signtures:
DEBUG:root:        Signature made 2019-02-06 22:39:57 using key ID 9DD1BB948581B0AD
DEBUG:root:            Richard Davis <crashvb>
INFO:root:Signature check passed.
```

Replicate both images to a local repository

```bash
$ docker pull registry:5000/crashvb/base:ubuntu
ubuntu: Pulling from crashvb/base
3b37166ec614: Download complete
504facff238f: Download complete
ebbcacd28e10: Download complete
c7fb3351ecad: Download complete
2e3debadcbf7: Download complete
a5396a146776: Download complete
6389d93ef5c7: Download complete
e05442215521: Download complete
f4ed07aa21a9: Download complete
e41e7b47a71d: Download complete
ae19c1f4b6b1: Download complete
Digest: sha256:8acac09a29bb9364dca10cce18e7d2fd4f83cb495a8519af585b56bcfeba03ca
Status: Downloaded newer image for registry:5000/crashvb/base:ubuntu
```

```bash
$ docker pull registry:5000/crashvb/base:ubuntu_signed
ubuntu_signed: Pulling from crashvb/base
3b37166ec614: Already exists
504facff238f: Already exists
ebbcacd28e10: Already exists
c7fb3351ecad: Already exists
2e3debadcbf7: Already exists
a5396a146776: Already exists
6389d93ef5c7: Already exists
e05442215521: Already exists
f4ed07aa21a9: Already exists
e41e7b47a71d: Already exists
ae19c1f4b6b1: Already exists
Digest: sha256:36e6e7cae412993ba19c0cf9a4583d1988e7668b5ce8e959f1915aabd0bb3bb2
Status: Downloaded newer image for registry:5000/crashvb/base:ubuntu_signed
```

```bash
$ docker images --format="{{.ID}}" registry:5000/crashvb/base:ubuntu
8ff76ab7ecbe
```

```bash
$ docker images --format="{{.ID}}" registry:5000/crashvb/base:ubuntu_signed
d9e31c5898fe
```

### Environment Variables

| Variable | Default Value | Description |
| ---------| ------------- | ----------- |
| DSV_GPG_DATASTORE | ~/.gnupg | The GnuPG home directory. |
| DSV_PKI_DATASTORE | ~/.dsv.pem | The PKI key store and trust store (concatenated PEM entities). |
| DSV_DOCKERHUB_AUTH | auth.docker.io | The dockerhub authentication endpoint. |
| DSV_DEFAULT_REGISTRY | index.docker.io | The dockerhub registry API endpoint. |
| DSV_CREDENTIALS_STORE | ~/.docker/config.json | The docker credentials store. |
| DSV_KEYID | _None_ | Identifier of the signing key. For GnuPG this is the keyid. For PKI this is the path to PEM encoded private key. |
| DSV_KEYPASS | "" | The corresponding key passphrase. |
| DSV_KEYTYPE | GPG | The signature type. Either GPG or PKI.


## Development

[Source Control](https://github.com/crashvb/docker-sign-verify)
