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

    def _nc_resp_to_xml(self, s):
        try:
            #s = s.replace('<?xml version="1.0" encoding="utf-8"?>\r\n', '');
            #s = s.replace('<?xml version="1.0" encoding="utf-8"?>', '');
            sx = etree.fromstring(s);
            sa = etree.tostring(sx, pretty_print=True).decode("utf-8");
            return sa;
        except:
            return s;

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
        NC_NS = 'urn:ietf:params:xml:ns:netconf:base:1.0';
        if t == 'client-hello':
            ROOT = None;
            if self.host_type in ['nxos3000']:
                ROOT = etree.Element('{' + NC_NS + '}hello', nsmap={'nc': NC_NS});
                CAPS = etree.SubElement(ROOT, '{'+ NC_NS + '}capabilities');
                CAPS_1 = etree.SubElement(CAPS, '{'+ NC_NS + '}capability');
                CAPS_1.text = 'urn:ietf:params:netconf:base:1.1';
                CAPS_2 = etree.SubElement(CAPS, '{'+ NC_NS + '}capability');
                CAPS_2.text = 'urn:ietf:params:netconf:capability:startup:1.0';
            else:
                ROOT = etree.Element('hello');
                CAPS = etree.SubElement(ROOT, 'capabilities');
                CAPS_1 = etree.SubElement(CAPS, 'capability');
                CAPS_1.text = 'urn:ietf:params:netconf:base:1.1';
                CAPS_2 = etree.SubElement(CAPS, 'capability');
                CAPS_2.text = 'urn:ietf:params:netconf:capability:startup:1.0';
            if self.host_type not in ['nxos3000']:
                SESSION_ID = etree.SubElement(ROOT, 'session-id');
                SESSION_ID.text = self._nc_session_id();
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(ROOT, pretty_print=True);
        elif t == 'close-session':
            ROOT = etree.Element('rpc');
            ROOT.attrib['message-id'] = self._nc_session_id();
            ROOT.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            CLOSE_SESSION = etree.SubElement(ROOT, 'close-session');
            xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(ROOT, pretty_print=True);
        elif t == 'get-config':
            ROOT = None;
            if self.host_type in ['nxos3000']:
                ROOT = etree.Element('{' + NC_NS + '}rpc', nsmap={'nc': NC_NS});
                ROOT.attrib['message-id'] = self._nc_session_id();
                ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:nfcli';
                GET_CONFIG = etree.SubElement(ROOT, '{'+ NC_NS + '}get-config');
                GET_CONFIG_SOURCE = etree.SubElement(GET_CONFIG, '{'+ NC_NS + '}source');
                if p1 == 'running':
                    etree.SubElement(GET_CONFIG_SOURCE, '{'+ NC_NS + '}running');
                #if p2 == 'interfaces':
                #    GET_CONFIG_FILTER = etree.SubElement(GET_CONFIG, 'filter');
                #    GET_CONFIG_FILTER_CONFIG = etree.SubElement(GET_CONFIG_FILTER, 'Configuration');
                #    etree.SubElement(GET_CONFIG_FILTER_CONFIG, 'InterfaceConfigurationTable');
            else:
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


    def rpc(self, cmds=[]):
        ''' Communicate RPC messages over NETCONF Session '''

        self.logger.info('RPC Request: ' + '/'.join(cmds) + ' ...');

        rpc_msg = None;
        rpc_req = None;

        self.logger.info('length: ' + str(len(cmds)))

        if len(cmds) == 3:
            rpc_msg = cmds[0];
            rpc_req = self._nc_xml_build(rpc_msg, cmds[1], cmds[2]); 
        elif len(cmds) == 2:
            rpc_msg = cmds[0];
            rpc_req = self._nc_xml_build(rpc_msg, cmds[1]); 
        else:
            rpc_msg = cmds[0];
            rpc_req = self._nc_xml_build(rpc_msg);

        try:
            if rpc_msg not in ['client-hello']:
                self.logger.info('sending ' + rpc_msg + ' RPC message:\n' + str(rpc_req));
                while not self.nc_chan.send_ready():
                    self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                    time.sleep(2);
                rc = self.nc_chan.send(rpc_req);
                if rc == 0:
                    self.logger.error('failed to send rpc ' + rpc_msg + ' message, because the channel stream is closes ...');
                    self.error = True;
                    return;
                else:
                    self.logger.info('the rpc ' + rpc_msg + ' message (' + str(rc) + ') was sent successfully ...');
            
            if rpc_msg in ['client-hello']:
                self.logger.info('receiving server-hello RPC message ...');
            else:
                self.logger.info('receiving response to ' + rpc_msg + ' RPC message ...');
            while not self.nc_chan.recv_ready():
                self.logger.info(self.host +  ' is not ready to receive data via this NETCONF channel, waiting ... ');
                time.sleep(2);
            close_session_resp = self.nc_chan.recv(65536);
            self.logger.info('received response:\n' + self._nc_resp_to_xml(close_session_resp.decode("utf-8")));

            if rpc_msg in ['client-hello']:
                self.logger.info('sending ' + rpc_msg + ' RPC message:\n' + str(rpc_req));
                while not self.nc_chan.send_ready():
                    self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                    time.sleep(2);
                rc = self.nc_chan.send(rpc_req);
                if rc == 0:
                    self.logger.error('failed to send rpc ' + rpc_msg + ' message, because the channel stream is closes ...');
                    self.error = True;
                    return;
                else:
                    self.logger.info('the rpc ' + rpc_msg + ' message (' + str(rc) + ') was sent successfully ...');

        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            self.error = True;

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
            self.logger.info('SSH Password => **********');
            #self.logger.info('SSH Password => ' + str(self.password));
        else:
            self.logger.info('SSH PrivKey  => **********'); 

        #rpc_msg = self._nc_xml_build('client-hello');
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
