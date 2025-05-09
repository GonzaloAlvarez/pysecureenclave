=====================
Python Secure Enclave
=====================


Python package to retrieve secure configuration from an enclave, with encryption. It leverages and manages
Yubikeys to secure the information.


Features
--------

This tool is aimed to enable managing secrets and keys in a secure way, with the help of YubiKeys.

Key Management
++++++++++++++

** List Keys **

```bash
$ pysecureenclave key list
```

** Create new Key **

```bash
$ pysecureenclave key new
```

Card Management
++++++++++++++

** Configure Card **

```shell
$ pysecureenclave card config
```

** Move key to card **

```shell
$ pysecureenclave card importkey
```

License
-------

Copyright (c) 2025, Gonzalo Alvarez

GNU Affero General Public License v3.0 or later

