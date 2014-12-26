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
import datetime;
import traceback;

try:
    from pynetconf import NetConfSession;
except Exception as err:
    for e in err.args:
        print('%-26s | %s | %s | %s' % (str(datetime.datetime.now()), __file__.split('/')[-1] + '->global()', str(type(err).__name__), str(e)));
    sys.exit(1);

def main():
    func = 'main()';
    descr = 'PyNetConf - IETF Network Configuration Protocol Client Library\n\n';
    descr += 'examples:\n';
    descr += '  python3 tests/test.py -ho router -u admin -p Y2lzY28K -c "show interfaces" -l 5\n';
    descr += '    [note: "Y2lzY28K" is base64-encoded "cisco"]\n';
    descr += '  python3 tests/test.py -ho router -u admin -k ~/.ssh/id_rsa \\\n';
    descr += '                        -c "show interfaces; show version" -l 5\n';
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
    credgroup.add_argument('-k', '--key', dest='ipass', metavar='SSH_KEY_FILE_PATH', type=argparse.FileType('r'), help='SSH private key file path');
    cmd_group = parser.add_argument_group('directives')
    cmd_group.add_argument('-c', '--cmd', dest='icmd', metavar='COMMAND', type=str, required=True, help='commands');
    auth_group.add_argument('--check-fingerprint', dest='ifc', action='store_true', help='enable SSH fingerprint check');
    parser.add_argument('-l', '--log-level', dest='ilog', metavar='LOG_LEVEL', type=int, default=0, choices=range(1, 6), help='log level (default: 0)');
    args = parser.parse_args();

    try:
        nc = NetConfSession(args.ihost, args.iuser, args.ipass, args.iport, args.ifc, args.ilog);
        nc.show('log');

        nc.connect();
        nc.show('log');
        if nc.error:
            raise RuntimeError('connectivity issue');

        ''' display client and server capabilities '''
        nc.show('capabilities', 'client');    # alternatively, pprint.pprint(nc.capabilities['client']);
        nc.show('capabilities', 'server');    # alternatively, pprint.pprint(nc.capabilities['server']);

        ''' 

            +---------+-----------+-------------+--------------+--------------+-------------+---------+
            | Command | Cisco IOS | Cisco CatOS | Cisco IOS XE | Cisco IOS XR | Cisco NX-OS | Juniper |
            +---------+-----------+-------------+--------------+--------------+-------------+---------+
            | show run                                                                                |
            | show version                                                                            |
            | show interfaces                                                                         |
            +-----------------------------------------------------------------------------------------+

        '''

        for c in args.icmd:
            nc.cmd(c);
            if nc.resp:
                nc.show('response');
            if nc.error:
                raise RuntimeError('command request-response issues');
            if len(nc.log) > 0:
                nc.show('log');
        nc.close();

    except Exception as err:
        for e in err.args:
            print('%-26s | %s | %s | %s' % (str(datetime.datetime.now()), __file__.split('/')[-1] + '->' + func, str(type(err).__name__), str(e)));
        if args.ilog == 5:
            for i in str(traceback.format_exc()).splitlines():
                print('%-26s | %s | %s ' % (str(datetime.datetime.now()), __file__.split('/')[-1] + '->' + func, i));
        return;

if __name__ == '__main__':
    main();
