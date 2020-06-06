[![cryptoSecurityEncoder Homepage](https://img.shields.io/badge/cryptoSecurityEncoder-develop-orange.svg)](https://github.com/davidvelascogarcia/cryptoSecurityEncoder/tree/develop/programs) [![Latest Release](https://img.shields.io/github/tag/davidvelascogarcia/cryptoSecurityEncoder.svg?label=Latest%20Release)](https://github.com/davidvelascogarcia/cryptoSecurityEncoder/tags) [![Build Status](https://travis-ci.org/davidvelascogarcia/cryptoSecurityEncoder.svg?branch=develop)](https://travis-ci.org/davidvelascogarcia/cryptoSecurityEncoder)

# Crypto Security Encoder: cryptoSecurityEncoder (Python API)

- [Introduction](#introduction)
- [Use](#use)
- [Requirements](#requirements)
- [Status](#status)
- [Related projects](#related-projects)


## Introduction

`cryptoSecurityEncoder` module use `pycryptodome` in `python`. This module encrypt and decrypt data using `AES` with 256 and 512 mode selected by the user. Use authenticated modes to verify the message. Also use functions to derivate the user key.


## Use

`cryptoSecurityEncoder` requires data to encrypt.
The process to running the program:

1. Execute [programs/cryptoSecurityEncoder.py](./programs), to start de program.
```python
python cryptoSecurityEncoder.py
```

## Requirements

`cryptoSecurityEncoder` requires:

* [Install pip](https://github.com/roboticslab-uc3m/installation-guides/blob/master/install-pip.md)
* Install pycryptodome:

```bash
pip3 install pycryptodome
```

Tested on: `windows 10`, `ubuntu 14.04`, `ubuntu 16.04`, `ubuntu 18.04`, `lubuntu 18.04` and `raspbian`.


## Status

[![Build Status](https://travis-ci.org/davidvelascogarcia/cryptoSecurityEncoder.svg?branch=develop)](https://travis-ci.org/davidvelascogarcia/cryptoSecurityEncoder)

[![Issues](https://img.shields.io/github/issues/davidvelascogarcia/cryptoSecurityEncoder.svg?label=Issues)](https://github.com/davidvelascogarcia/cryptoSecurityEncoder/issues)

## Related projects

* [PyCryptodome: docs](https://pypi.org/project/pycryptodome/)

