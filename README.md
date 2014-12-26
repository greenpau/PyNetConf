PyNetConf
=========

IETF Network Configuration Protocol (NETCONF) Client Library


Testing
-------

```
usage: test.py [-h] -ho HOST [-po PORT] -u USERNAME
               (-p PASSWORD | -k SSH_KEY_FILE_PATH) -c COMMAND
               [--check-fingerprint] [-l LOG_LEVEL]

PyNetConf - IETF Network Configuration Protocol Client Library

examples: [note: "Y2lzY28K" is base64-encoded "cisco"]
  python3 tests/test.py -ho router -u admin -p Y2lzY28K -c "show interfaces" -l 5
  python3 tests/test.py -ho router -u admin -k ~/.ssh/id_rsa \
                        -c "show interfaces; show version" -l 5
  python3 tests/test.py --help

optional arguments:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        log level (default: 0)

network connectivity arguments:
  -ho HOST, --host HOST
                        host IP or DNS Name
  -po PORT, --port PORT
                        tcp port (default: 830)

authentication arguments:
  -u USERNAME, --user USERNAME
                        username
  -p PASSWORD, --pass PASSWORD
                        base64-encoded password
  -k SSH_KEY_FILE_PATH, --key SSH_KEY_FILE_PATH
                        SSH private key file path
  --check-fingerprint   enable SSH fingerprint check

directives:
  -c COMMAND, --cmd COMMAND
                        commands

documentation:
  https://github.com/greenpau/PyNetConf

```
