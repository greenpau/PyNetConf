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
import random;


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


    def _xml_to_dict_list(self, el):
        rl = {};
        rc = {}
        for e in el:
            if e.tag in rl:
                rl[e.tag] += 1;
            else:
                rl[e.tag] = 1;
            if e.tag in rc:
                if rc[e.tag] < len(e.getchildren()):
                    rc[e.tag] = len(e.getchildren());
            else:
                rc[e.tag] = len(e.getchildren());
        ''' determine whether there are duplicate elements for auto-numbering purposes '''
        for r in rl:
            if rl[r] > 1:
                return 1;
        return 0;


    def _xml_to_dict_ns(self, s):
        nsmap = { 
            '{urn:ietf:params:xml:ns:netconf:base:1.0}': 'nc',
        };
        for ns in nsmap:
            if re.match(ns, s):
                s = re.sub(ns, nsmap[ns] + ':', s) 
        return s;


    def _xml_to_dict(self, c0):
        if len(c0.getchildren()) == 0:
            return None, None;
        db = {};
        id = None;
        c0_tag = self._xml_to_dict_ns(c0.tag);

        try:
            f = db[c0_tag];
        except:
            db[c0_tag] = {};

        c1_incr = 0;
        for c1 in c0.getchildren():
            c1_tag = self._xml_to_dict_ns(c1.tag);
            if self._xml_to_dict_list(list(c0)) > 0:
                c1_incr += 1;
                c1_tag = c1_tag + '_' + str(c1_incr);
            if len(c1.getchildren()) == 0:
                db[c0_tag][c1_tag] = str(c1.text);
            else:
                try:
                    f = db[c0_tag][c1_tag];
                except:
                    db[c0_tag][c1_tag] = {};
                c2_incr = 0;
                for c2 in c1.getchildren():
                    c2_tag = self._xml_to_dict_ns(c2.tag);
                    if self._xml_to_dict_list(list(c1)) > 0:
                        c2_incr += 1;
                        c2_tag = c2_tag + '_' + str(c2_incr);
                    if len(c2.getchildren()) == 0:
                        db[c0_tag][c1_tag][c2_tag] = str(c2.text);
                    else:
                        try:
                            f = db[c0_tag][c1_tag][c2_tag];
                        except:
                            db[c0_tag][c1_tag][c2_tag] = {};
                    c3_incr = 0;
                    for c3 in c2.getchildren():
                        c3_tag = self._xml_to_dict_ns(c3.tag);
                        if self._xml_to_dict_list(list(c2)) > 0:
                            c3_incr += 1;
                            c3_tag = c3_tag + '_' + str(c3_incr);
                        if len(c3.getchildren()) == 0:
                            db[c0_tag][c1_tag][c2_tag][c3_tag] = str(c3.text);
                        else:
                            try:
                                f = db[c0_tag][c1_tag][c2_tag][c3_tag];
                            except:
                                db[c0_tag][c1_tag][c2_tag][c3_tag] = {};
        if 'nc:hello' in db:
            if 'nc:session-id' in db['nc:hello']:
                id = db['nc:hello']['nc:session-id']; 

        if c0.attrib:
            if c0.attrib.get('message-id'):
                id = c0.attrib['message-id'];

        return db, id;


    def _nc_resp_to_xml(self, s):
        rpc_end = False;
        rpc_encoding = False;
        try:
            if not isinstance(s, str):
                sa = s.decode("utf-8");
            else:
                sa = s;
            if re.search(r'\r?\n?]]>]]>$', sa, re.DOTALL):
                self.logger.info('found end of RPC response ...');
                sa = re.sub(r'\r?\n?]]>]]>', '', sa)
                rpc_end = True;
            if re.search(r'<\?xml version.*encoding.*\?>', sa, re.MULTILINE):
                self.logger.info('found encoding of RPC response ...');
                sa = re.sub(r'<\?xml version.*encoding.*\?>\r?\n?', '', sa)
                rpc_encoding = True;
            root = etree.fromstring(sa);
            sa = etree.tostring(root, pretty_print=True).decode("utf-8");
            sd, id = self._xml_to_dict(root);
            return sa, sd, id;
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            return s, None, None;

    def _nc_xml_valid(self, p=None, s=None):
        v = False;
        self.logger.info('validating XML for session-id/message-id ' + str(self.sid) + '/' + str(self.mid) + ' ...');
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
            self.logger.info('XML document for session-id/message-id ' + str(self.sid) + '/' + str(self.mid) + ' passed validate() validation ...')
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            v = False;
        self.logger.info('using assertValid() ...');
        try:
            x.assertValid(etree.fromstring(p));
            v = True;
            self.logger.info('XML document for session-id/message-id ' + str(self.sid) + '/' + str(self.mid) + ' passed assertValid() validation ...')
        except Exception as err:
            self.logger.error(str(err));
            self.logger.error(str(traceback.format_exc()));
            v = False;
        return v;

        
    def _nc_session_id(self):
        self.sid += 1;
        return str(self.sid);


    def _nc_message_id(self):
        self.mid += 1;
        return str(self.mid);


    def _nc_xml_build(self, args):
        pprint.pprint(args);
        self.logger.info('Building ' + args[0] + ' ...');
        xb = None;
        xa = None;
        NC_NS = 'urn:ietf:params:xml:ns:netconf:base:1.0';
        XML_NS = 'http://www.w3.org/2001/XMLSchema-instance';
        NF_NS = 'http://www.cisco.com/nxos:1.0:nfcli';
        ROOT = None;

        if args[0] == 'client-hello':
            if self.host_type in ['n3k']:
                ROOT = etree.Element('{' + NC_NS + '}hello', nsmap={'nc': NC_NS});
                CAPS = etree.SubElement(ROOT, '{'+ NC_NS + '}capabilities');
                CAPS_1 = etree.SubElement(CAPS, '{'+ NC_NS + '}capability');
                CAPS_1.text = 'urn:ietf:params:netconf:base:1.0';
            else:
                ROOT = etree.Element('hello');
                CAPS = etree.SubElement(ROOT, 'capabilities');
                CAPS_1 = etree.SubElement(CAPS, 'capability');
                CAPS_1.text = 'urn:ietf:params:netconf:base:1.0';
                CAPS_2 = etree.SubElement(CAPS, 'capability');
                CAPS_2.text = 'urn:ietf:params:netconf:capability:startup:1.0';
            if self.host_type not in ['n3k']:
                SESSION_ID = etree.SubElement(ROOT, 'session-id');
                SESSION_ID.text = self._nc_session_id();
        elif args[0] == 'close-session':
            ROOT = etree.Element('rpc');
            ROOT.attrib['message-id'] = self._nc_message_id();
            ROOT.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
            CLOSE_SESSION = etree.SubElement(ROOT, 'close-session');
        elif args[0] == 'edit-config':
            if self.host_type in ['n3k']:
                ROOT = etree.Element('{' + NC_NS + '}rpc', nsmap={'nc': NC_NS});
                ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:if_manager';
                ROOT.attrib['message-id'] = self._nc_message_id();
                CONF = etree.SubElement(ROOT, '{'+ NC_NS + '}edit-config');
                CONF_TARGET = etree.SubElement(CONF, '{'+ NC_NS + '}target');                
                if args[1] == 'running':
                    etree.SubElement(CONF_TARGET, '{'+ NC_NS + '}running');
                else:
                    self.logger.error('unsupported config mode: ' + args[1]);
                    self.error = True;
                    return;
                CONF_CH = etree.SubElement(CONF, '{'+ NC_NS + '}config');
                CONF_CH_INIT = etree.SubElement(CONF_CH, 'configure');
                CONF_CH_MODE = etree.SubElement(CONF_CH_INIT, '__XML__MODE__exec_configure');
                if args[2] == 'interface':
                    CONF_CH_IFS = etree.SubElement(CONF_CH_MODE, 'interface');
                else:
                    self.logger.error('unsupported config section: ' + args[2]);
                    self.error = True;
                    return;
                if args[3] == 'ethernet':
                    CONF_CH_IFTYPE = etree.SubElement(CONF_CH_IFS, 'ethernet');
                    CONF_CH_IF = etree.SubElement(CONF_CH_IFTYPE, 'interface');
                    CONF_CH_IF.text = str(args[4]);
                    CONF_CH_MODE_IF = etree.SubElement(CONF_CH_IFTYPE,'__XML__MODE_if-ethernet');
                    CONF_CH_MODE_IF_BASE = etree.SubElement(CONF_CH_MODE_IF, '__XML__MODE_if-eth-base');
                else:
                    self.logger.error('unsupported interface type: ' + args[3]);
                    self.error = True;
                    return;
                if args[5] == 'description':
                    CONF_CH_MODE_IF_BASE_SETTING = etree.SubElement(CONF_CH_MODE_IF_BASE, 'description');
                    CONF_CH_MODE_IF_BASE_SETTING_TEXT = etree.SubElement(CONF_CH_MODE_IF_BASE_SETTING, 'desc_line');
                    CONF_CH_MODE_IF_BASE_SETTING_TEXT.text = str(args[6]);
                else:
                    self.logger.error('unsupported interface setting: ' + args[5]);
                    self.error = True;
                    return;
        elif args[0] == 'get':
            if self.host_type in ['n3k']:
                ROOT = etree.Element('{' + NC_NS + '}rpc', nsmap={'nc': NC_NS});
                ROOT.attrib['message-id'] = self._nc_message_id();
                if args[1] == 'show' and args[2] in ['version', 'config']:
                    ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:sysmgrcli';
                if args[1] == 'show' and args[2] in ['xml']:
                    ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:xml';
                GET = etree.SubElement(ROOT, '{'+ NC_NS + '}get');
                GET_FILTER = etree.SubElement(GET, '{'+ NC_NS + '}filter');
                GET_FILTER.attrib['type'] = 'subtree';
                if args[1] == 'show':
                    GET_SHOW = etree.SubElement(GET_FILTER, 'show');
                if args[2] == 'version':
                    GET_SHOW_VER = etree.SubElement(GET_SHOW, 'version');
                if args[2] == 'config' and args[3] == 'running':
                    GET_SHOW_RUN = etree.SubElement(GET_SHOW, 'running-config');
                    GET_SHOW_RUN.text = '\n';
                if args[2] == 'xml' and args[3] == 'server' and args[4] == 'status':
                    GET_SHOW_XML = etree.SubElement(GET_SHOW, 'xml');
                    GET_SHOW_XML_SERVER = etree.SubElement(GET_SHOW_XML, 'server');
                    GET_SHOW_XML_SERVER_STATUS = etree.SubElement(GET_SHOW_XML_SERVER, 'status');
        elif args[0] == 'get-config':
            if self.host_type in ['n3k']:
                self.logger.error('get-config is unsupported on Cisco Nexus 3K platform, exiting ...');
                sys.exit(1);
            else:
                ROOT = etree.Element('rpc');
                ROOT.attrib['message-id'] = self._nc_message_id();
                ROOT.attrib['xmlns'] = 'urn:ietf:params:xml:ns:netconf:base:1.0';
                ROOT.attrib['xmlns'] = 'http://www.cisco.com/nxos:1.0:nfcli';
                GET_CONFIG = etree.SubElement(ROOT, 'get-config');
                GET_CONFIG_SOURCE = etree.SubElement(GET_CONFIG, 'source');
                if args[1] == 'running':
                    etree.SubElement(GET_CONFIG_SOURCE, 'running');
                if args[2] == 'interfaces':
                    GET_CONFIG_FILTER = etree.SubElement(GET_CONFIG, 'filter');
                    GET_CONFIG_FILTER_CONFIG = etree.SubElement(GET_CONFIG_FILTER, 'Configuration');
                    etree.SubElement(GET_CONFIG_FILTER_CONFIG, 'InterfaceConfigurationTable');
        else:
            self.logger.error(args[0] + ' is unrecognized netconf type, exiting ...');
            sys.exit(1);

        xb = b'<?xml version="1.0" encoding="utf-8"?>\n' + etree.tostring(ROOT, pretty_print=True);
        xa = xb.decode("utf-8");
        if self.xml_validation == True:
            if self._nc_xml_valid(xa) == False:
                self.logger.error('failed netconf xml schema validation for ' + t + ' ...');
        self.logger.info('Building ' + args[0] + ' ... done');
        return xa + ']]>]]>';


    def _rpc_filter(self, cmd):
        r = [];
        if cmd is None:
            return None;
        rgx_int = re.match(r'(edit-config) (running) (interface) (ethernet) (\d+/\d+) (description) \'(.*)\'$', cmd);
        if re.match('client-hello', cmd):
            return(['client-hello']);
        elif re.match('close-session', cmd):
            return(['close-session']);
        elif rgx_int:
            for i in range(1, 8):
                r.append(rgx_int.group(i));
            return r;
        else:
            self.logger.error('unsupported RPC: ' + cmd);
            self.error = True;
            return None;

    def rpc(self, cmd):
        ''' Communicate RPC messages over NETCONF Session '''

        cmds = self._rpc_filter(cmd);
        if cmds is None:
            return;

        self.logger.info('RPC Request: ' + '/'.join(cmds) + ' ...');

        rpc_action = cmds[0];
        rpc_req = self._nc_xml_build(cmds);

        if rpc_req is None:
            return;

        try:
            if rpc_action not in ['client-hello']:
                self.logger.info('sending ' + rpc_action + ' RPC message:\n' + str(rpc_req));
                while not self.nc_chan.send_ready():
                    self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                    time.sleep(2);
                rc = self.nc_chan.send(rpc_req);
                if rc == 0:
                    self.logger.error('failed to send rpc ' + rpc_action + ' message, because the channel stream is closes ...');
                    self.error = True;
                    return;
                else:
                    self.logger.info('the rpc ' + rpc_action + ' message (' + str(rc) + ') was sent successfully ...');

            
            ''' receiving rpc message '''
            if rpc_action in ['client-hello']:
                self.logger.info('receiving server-hello RPC message ...');
            else:
                self.logger.info('receiving response to ' + rpc_action + ' RPC message ...');
            while not self.nc_chan.recv_ready():
                self.logger.info(self.host +  ' is not ready to receive data via this NETCONF channel, waiting ... ');
                time.sleep(2);
            rpc_resp_raw = self.nc_chan.recv(65536);
            rpc_resp_xml, rpc_resp_dict, rpc_id = self._nc_resp_to_xml(rpc_resp_raw);
            if rpc_id is not None:
                self.logger.info('received XML response (' + rpc_id + '):\n' + rpc_resp_xml);
                self.logger.info('dictionary:\n' + pprint.pformat(rpc_resp_dict));
            else:
                self.logger.error('failed to parse rpc ' + rpc_action + ' response message ...');
                self.logger.error('review the received XML rpc response:\n' + str(rpc_resp_raw));
                self.error = True;
                return;
            if rpc_action in ['client-hello']:
                self.sid = int(rpc_id);


            ''' sending client hello rpc message '''
            if rpc_action in ['client-hello']:
                rpc_req = self._nc_xml_build(['client-hello']);
                self.logger.info('sending ' + rpc_action + ' RPC message:\n' + str(rpc_req));
                while not self.nc_chan.send_ready():
                    self.logger.info('NETCONF channel to ' + self.host +  ' is busy, waiting ... ');
                    time.sleep(2);
                rc = self.nc_chan.send(rpc_req);
                if rc == 0:
                    self.logger.error('failed to send rpc ' + rpc_action + ' message, because the channel stream is closes ...');
                    self.error = True;
                    return;
                else:
                    self.logger.info('the rpc ' + rpc_action + ' message (' + str(rc) + ') was sent successfully ...');

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

        self.sid = 0;
        self.mid = random.randrange(2000, 10000);
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
            if host_type in ['n3k']:
                self.host_type = host_type;
            else:
                self.logger.error('the only supported type(s): n3k');
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

        #rpc_action = self._nc_xml_build('client-hello');
        #rpc_action = self._nc_xml_build('get-config', 'running', 'interfaces');
        #print(rpc_action);
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
            self.error = True;
        return;
