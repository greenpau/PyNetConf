#!/usr/bin/env python

#------------------------------------------------------------------------------------------#
# File:      test.py                                                                       #
# Purpose:   PyNetConf - IETF Network Configuration Protocol Client Library                #
# Author:    Paul Greenberg                                                                #
# Version:   1.0                                                                           #
# Copyright: (c) 2014 Paul Greenberg <paul@greenberg.pro>                                  #
#------------------------------------------------------------------------------------------#

import os;
import sys;
if sys.version_info[0] < 3:
    sys.stderr.write(os.path.basename(__file__) + ' requires Python 3 or higher.\n');
    sys.stderr.write("python3 " + __file__ + '\n');
    sys.exit(1);
sys.path.append(os.path.join('/'.join(os.path.abspath(__file__).split('/')[:-2])));
import argparse;
import pprint;
import traceback;

try:
    from pynetconf import NetConfSession;
except Exception as err:
    print('%-10s %s' % ('import():', 'Error: ' + str(err)));
    for i in str(traceback.format_exc()).splitlines():
        print('%-10s %s' % ('import():', i));
    sys.exit(1);

def main():    
    func = 'main()';
    descr = 'PyNetConf - IETF Network Configuration Protocol Client Library\n\n';
    descr += 'examples:\n';
    descr += '  python3 tests/test.py -ho router -u admin -p Y2lzY28K -l 10\n';
    descr += '    [note: "Y2lzY28K" is base64-encoded "cisco"]\n';
    descr += '  python3 tests/test.py --help';
    epil = 'documentation:\n  https://github.com/greenpau/PyNetConf\n \n';
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description=descr, epilog=epil);
    conn_group = parser.add_argument_group('network connectivity arguments')
    conn_group.add_argument('-ho', '--host', dest='ihost', metavar='HOST', type=str, required=True, help='host IP or DNS Name');
    conn_group.add_argument('-po', '--port', dest='iport', metavar='PORT', type=int, default=830, help='tcp port (default: 830)');
    auth_group = parser.add_argument_group('authentication arguments')
    auth_group.add_argument('-u', '--user', dest='iuser', metavar='USERNAME', type=str, required=True, help='username');
    credgroup = auth_group.add_mutually_exclusive_group(required=True);
    credgroup.add_argument('-p', '--pass', dest='ipass', metavar='PASSWORD', type=str, help='base64-encoded password');
    credgroup.add_argument('-k', '--key', dest='ikey', metavar='SSH_KEY_FILE_PATH', type=argparse.FileType('r'), help='SSH private key file path');
    auth_group.add_argument('-c', '--check-fingerprint', dest='FINGERPRINT_CHECK', action='store_true', help='enable SSH fingerprint check');

    parser.add_argument('-l', '--log', dest='ilog', metavar='LEVEL', type=int, default=0, help='log level (default: 0)');
    args = parser.parse_args();

    if args.ilog < 20:
        print('%-10s %s = %d' % (func + ':', 'log level', args.ilog));

    try:
        nc = NetConfSession();
    except Exception as err:
        print('%-10s %s' % (func + ':', 'Error: ' + str(err)));
        for i in str(traceback.format_exc()).splitlines():
            print('%-10s %s' % ('import():', i));
        return;

if __name__ == '__main__':
    main();
