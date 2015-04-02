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
import logging;
import socket;
import time;

class NetConfSession:
    ''' Represents NETCONF Session '''

    def show(self, t=None, p=None):
        if t == 'capabilities':
            ''' Display client or server NETCONF capabilities from hello message exchange'''
            if p == 'client':
                pass;
            elif p == 'server':
                pass;
            else:
                pass;
        else:
            pass;
        return;

    def _nc_xml_valid(self, p=None, s=None):
        v = False;
        self.logger.info('Validating XML for session-id ' + str(self.sid) + ' ...');
        if s is None:
            s = 'xml/netconf.xsd';
        if not isinstance(p, bytes):
            p = bytes(p, 'utf-8');
        try:
            xsd = os.path.join('/'.join(os.path.abspath(__file__).split('/')[:-1]), s);
            self.logger.info('against ' + xsd + ' ...');
            x = etree.XMLSchema(file=xsd);
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
        self.logger.info('using validate() ...');
        try:
            x.validate(etree.fromstring(p));
            v = True;
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            v = False;
        self.logger.info('using assertValid() ...');
        try:
            x.assertValid(etree.fromstring(p));
            v = True;
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            v = False;
        return v;
        
    def _nc_session_id(self):
        self.sid += 1;
        return str(self.sid);

    def _nc_xml_build(self, t, p1=None, p2=None):
        self.logger.info('Building ' + t + ' ...');
        xb = None;
        xa = None;
        if t == 'client_hello':
            HELLO = etree.Element('hello');
            HELLO.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            CAPS = etree.SubElement(HELLO, 'capabilities');
            CAPS_1 = etree.SubElement(CAPS, 'capability');
            CAPS_1.text = 'urn:ietf:params:netconf:base:1.1';
            CAPS_2 = etree.SubElement(CAPS, 'capability');
            CAPS_2.text = 'urn:ietf:params:netconf:capability:startup:1.0';
            #SESSION_ID = etree.SubElement(HELLO, 'session-id');
            #SESSION_ID.text = self._nc_session_id();
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(HELLO, pretty_print=True);
        elif t == 'close-session':
            ROOT = etree.Element('rpc');
            ROOT.attrib['message-id'] = self._nc_session_id();
            ROOT.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            CLOSE_SESSION = etree.SubElement(ROOT, 'close-session');
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(ROOT, pretty_print=True);
        elif t == 'get-config':
            ROOT = etree.Element('rpc');
            ROOT.attrib['message-id'] = self._nc_session_id();
            ROOT.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:nfcli';
            GET_CONFIG = etree.SubElement(ROOT, 'get-config');
            GET_CONFIG_SOURCE = etree.SubElement(GET_CONFIG, 'source');
            if p1 == 'running':
                etree.SubElement(GET_CONFIG_SOURCE, 'running');
            if p2 == 'interfaces':
                GET_CONFIG_FILTER = etree.SubElement(GET_CONFIG, 'filter');
                GET_CONFIG_FILTER_CONFIG = etree.SubElement(GET_CONFIG_FILTER, 'Configuration');
                etree.SubElement(GET_CONFIG_FILTER_CONFIG, 'InterfaceConfigurationTable');
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(ROOT, pretty_print=True);
        else:
            self.logger.error('unrecognized netconf type => ' + t);
            sys.exit(1);
        xa = xb.decode("utf-8");
        if self.xml_validation == True:
            if self._nc_xml_valid(xa) == False:
                self.logger.error('failed netconf xml schema validation for ' + t + ' ...');
        self.logger.info('Building ' + t + ' ... done');
        return xa + ']]>]]>';


    def connect(self):
        ''' Exchange hello messages '''

        client_hello = self._nc_xml_build('client_hello');

        try:
            self.logger.info('receiving server hello message ...');
            while not self.nc_chan.recv_ready():
                self.logger.info(self.host +  ' is not ready to receive data via this NETCONF channel, waiting ... ');
                time.sleep(2);
            server_hello = self.nc_chan.recv(65536);
            self.logger.info('received server hello message:\n' + str(server_hello));


            self.logger.info('sending client hello message:\n' + str(client_hello));
            while not self.nc_chan.send_ready():
                self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                time.sleep(2);
            self.nc_chan.send(client_hello);
            self.logger.info('completed sending client hello message ...');

        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            self.error = True;

        return;


    def cmd(self, cmd=None):
        ''' Craft XML payload, send it, and parse XML response '''
        self.logger.info('Executing ' + str(cmd) + ' ...');

        rpc_req = self._nc_xml_build('get-config', 'running', 'interfaces');

        try:
            self.logger.info('sending rpc message:\n' + str(rpc_req));
            while not self.nc_chan.send_ready():
                self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                time.sleep(2);
            self.nc_chan.send(rpc_req);
            self.logger.info('completed sending rpc message ...');

            self.logger.info('receiving response ...');
            while not self.nc_chan.recv_ready():
                self.logger.info(self.host +  ' is not ready to receive data via this NETCONF channel, waiting ... ');
                time.sleep(2);

            rpc_resp = self.nc_chan.recv(65536);

            self.logger.info('received response:\n' + str(rpc_resp));

        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            self.error = True;

        return;


    def close(self):
        ''' Terminate NETCONF Session via close-session operation '''

        close_session_req = self._nc_xml_build('close-session');

        try:
            self.logger.info('sending close-session message:\n' + str(close_session_req));
            while not self.nc_chan.send_ready():
                self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                time.sleep(2);
            self.nc_chan.send(close_session_req);
            self.logger.info('completed sending close-session message ...');

#            ....#
#
#            self.logger.info('receiving response ...');
#            while not self.nc_chan.recv_ready():
#                self.logger.info(self.host +  ' is not ready to receive data via this NETCONF channel, waiting ... ');
#                time.sleep(2);

#            close_session_resp = self.nc_chan.recv(65536);

#            self.logger.info('received response:\n' + str(close_session_resp));

        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            self.error = True;

        return;


    def kill(self):
        ''' Terminate NETCONF Session via kill-session operation '''
        return;


    def __init__(self, host=None, host_type=None, user=None, password=None, port=830, 
                 check_fingerprint=False, verbose=0, xml_validation=False):
        ''' Initialize NETCONF Session '''
        logging.basicConfig(format='%(asctime)s - %(name)s - %(funcName)s() - %(levelname)s - %(message)s');
        self.logger = logging.getLogger(__name__);

        if verbose == 1:
            self.logger.setLevel(logging.WARN);
        elif verbose == 2:
            self.logger.setLevel(logging.INFO);
        elif verbose == 3:
            self.logger.setLevel(logging.DEBUG);
        else:
            self.logger.setLevel(logging.ERROR);

        self.sid = 1000;
        self.error = False;
        self.resp = None;
        self.capabilities = {'client': None, 'server': None};
        self.xml_validation = xml_validation;

        if isinstance(host, str):
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                self.host = host;
            else:
                self.host = host;
        else:
            self.logger.error('expects host parameter to be a string');
            self.error = True;
            return;

        if isinstance(host_type, str):
            if host_type in ['nxos3000']:
                self.host_type = host_type;
            else:
                self.logger.error('the only supported type(s): nxos3000');
                self.error = True;
                return;
        else:
            self.logger.error('expects host type parameter to be a string');
            self.error = True;
            return;
        

        if isinstance(port, int):
            if port in range(1, 65535):
                self.port = port;
            else:
                self.logger.error('expects TCP port parameter value to be between 1 and 65535');
                self.error = True;
                return;
        else:
            self.logger.error('expects TCP port parameter to be an integer');
            self.error = True;
            return;

        if isinstance(user, str):
            self.username = user;
        else:
            self.logger.error('expects user parameter to be a string');
            self.error = True;
            return;

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
            self.logger.error('invalid authentication method ' + str(type(password)));
            self.error = True;
            return;

        self.logger.info('Log Level    => ' + str(verbose));
        self.logger.info('Host         => ' + self.host);
        self.logger.info('Type         => ' + self.host_type);
        self.logger.info('TCP Port     => ' + str(self.port));
        self.logger.info('Username     => ' + self.username);
        self.logger.info('Auth Method  => ' + self.auth);
        if self.auth == 'password':
            self.logger.info('SSH Password => ' + str(self.password));
        else:
            self.logger.info('SSH PrivKey  => ' + str(self.password)); 

        #rpc_msg = self._nc_xml_build('get-config', 'running', 'interfaces');
        #print(rpc_msg);
        #sys.exit(1)

        try:
            self.nc_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM);
            self.nc_sock.connect((self.host, self.port));
            self.nc_trans = paramiko.Transport(self.nc_sock);
            self.nc_trans.connect(username=self.username, password=self.password);
            self.nc_chan = self.nc_trans.open_session();
            self.nc_chan.invoke_subsystem('xmlagent');
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            
        return;
