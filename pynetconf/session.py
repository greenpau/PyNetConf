#   PyNetConf - IETF Network Configuration Protocol (NETCONF) Client Library
#   Copyright (C) 2014 Paul Greenberg <paul@greenberg.pro>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os;
import sys;
import io;
import datetime;
import traceback;
import re;
import pprint;
import base64;
from lxml import etree;
import paramiko;

class NetConfSession:
    ''' Represents NETCONF Session '''

    def _exit(self, lvl=0):
        if self.verbose > 0:
            if self.log:
                print('\n'.join(self.log));
        else:
            if self.err:
                print('\n'.join(self.err));
        if lvl == 1:
            exit(1);
        else:
            exit(0);


    def _log(self, msg='TEST', lvl='INFO'):
        ''' Logging '''
        if self.verbose < 1 and lvl == 'INFO':
            return;
        lvls={'DEBUG': 5, 'CRIT': 4, 'ERROR': 3, 'WARN': 2, 'INFO': 1};
        cls = str(type(self).__name__);
        func = str(sys._getframe(1).f_code.co_name);
        ts = str(datetime.datetime.now());
        for xmsg in msg.split('\n'):
            if self.error is not True and lvls[lvl] in [3, 4]:
                self.error = True;
            self._log_id += 1;
            self.log[self._log_id] = {'ts': ts, 'function': __file__.split('/')[-1] + '->' + cls + '.' + func + '()', 'level': lvl, 'text': xmsg};
        return;


    def show(self, t=None, p=None):
        ''' Display information '''
        if t == 'log':
            ''' Display log buffer '''
            for x in self.log:
                if p == 'error' and self.log[x][level] not in ['CRIT', 'ERROR']:
                    continue;
                print("{0:26s} | {1:s} | {2:s} | {3:s}".format(self.log[x]['ts'], 
                                                               self.log[x]['function'], 
                                                               self.log[x]['level'],
                                                               self.log[x]['text']));
        elif t == 'capabilities':
            ''' Display client or server NETCONF capabilities from hello message exchange'''
            if p == 'client':
                pass;
            elif p == 'server':
                pass;
            else:
                pass;
        else:
            pass;
        self.log.clear();
        return;

    def _nc_xml_valid(self, p=None, s=None):
        v = False;
        self._log('Validating XML for session-id ' + str(self.sid) + ' ...', 'INFO');
        if s is None:
            s = 'xml/netconf.xsd';
        if not isinstance(p, bytes):
            p = bytes(p, 'utf-8');
        try:
            xsd = os.path.join('/'.join(os.path.abspath(__file__).split('/')[:-1]), s);
            self._log('against ' + xsd + ' ...', 'INFO');
            x = etree.XMLSchema(file=xsd);
        except Exception as err:
            self._log(str(err), 'ERROR');
            self._log(str(traceback.format_exc()), 'ERROR');
        self._log('using validate() ...', 'INFO');
        try:
            x.validate(etree.fromstring(p));
            v = True;
        except Exception as err:
            self._log(str(err), 'ERROR');
            self._log(str(traceback.format_exc()), 'ERROR');
            v = False;
        self._log('using assertValid() ...', 'INFO');
        try:
            x.assertValid(etree.fromstring(p));
            v = True;
        except Exception as err:
            self._log(str(err), 'ERROR');
            self._log(str(traceback.format_exc()), 'ERROR');
            v = False;
        return v;
        
    def _nc_session_id(self):
        self.sid += 1;
        return str(self.sid);

    def _nc_xml_build(self, t, p1=None, p2=None):
        self._log('Building ' + t + ' ...', 'INFO');
        if t == 'hello':
            HELLO = etree.Element('hello');
            HELLO.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            CAPS = etree.SubElement(HELLO, 'capabilities');
            CAPS_1 = etree.SubElement(CAPS, 'capability');
            CAPS_1.text = 'urn:ietf:params:netconf:base:1.1';
            CAPS_2 = etree.SubElement(CAPS, 'capability');
            CAPS_2.text = 'urn:ietf:params:netconf:capability:startup:1.0';
            SESSION_ID = etree.SubElement(HELLO, 'session-id');
            SESSION_ID.text = self._nc_session_id();
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(HELLO, pretty_print=True);
            xa = xb.decode("utf-8");
            if self._nc_xml_valid(xa) == False:
                self._log('failed netconf xml schema validation for ' + t + ' ...', 'ERROR');
        self._log('Building ' + t + ' ... done', 'INFO');
        return xa;


    def connect(self):
        ''' Initialize SSH Session and exchange hello messages '''
        self._log('Connecting ...', 'INFO');
        x = self._nc_xml_build('hello');
        print(str(x));

        return;

    def cmd(self, cmd=None):
        ''' Craft XML payload, send it, and parse XML response '''
        self._log('Executing ' + str(cmd) + ' ...', 'INFO');
        return;


    def close(self):
        ''' Terminate NETCONF Session via close-session operation '''
        return;


    def kill(self):
        ''' Terminate NETCONF Session via kill-session operation '''
        return;


    def __init__(self, host=None, user=None, password=None, port=830, check_fingerprint=False, verbose=0):
        ''' Initialize NETCONF Session '''

        self.verbose = verbose;

        self.log = {};
        self._log_id = 0;
        self.sid = 0;
        self.error = False;
        self.resp = None;
        self.capabilities = {'client': None, 'server': None};

        if isinstance(host, str):
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                self.host = host;
            else:
                self.host = host;
        else:
            self._log('expects host parameter to be a string', 'ERROR');
            self._exit(1);

        if isinstance(port, int):
            if port in range(1, 65535):
                self.port = port;
            else:
                self._log('expects TCP port parameter value to be between 1 and 65535', 'ERROR');
                self._exit(1);
        else:
            self._log('expects TCP port parameter to be an integer', 'ERROR');
            self._exit(1);        

        if isinstance(user, str):
            self.username = user;
        else:
            self._log('expects user parameter to be a string', 'ERROR');
            self._exit(1);

        self.check_fingerprint = check_fingerprint;

        ''' check whether password is a string or file path '''
        if isinstance(password, str):
            self.auth='password';
            #self.password=base64.standard_b64decode(password).decode("utf-8").strip();
            self.password=password;
        elif isinstance(password, io.TextIOWrapper):
            self.auth='publickey';
            self.password='publickey';
        else:
            self._log('invalid authentication method ' + str(type(password)), 'ERROR');
            self._exit(1);

        if self.verbose > 0:
            self._log('Log Level = ' + str(self.verbose), 'INFO');
            self._log('Host = ' + self.host, 'INFO');
            self._log('TCP Port = ' + str(self.port), 'INFO');
            self._log('Username = ' + self.username, 'INFO');
            self._log('Authentication Method = ' + self.auth, 'INFO');
            if self.auth == 'password':
                self._log('SSH Password = ' + str(self.password), 'INFO');
            else:
                self._log('SSH Private Key = ' + str(self.password), 'INFO'); 
            
        return;

