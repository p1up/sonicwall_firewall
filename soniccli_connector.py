# -----------------------------------------
# SonicWALL App Connector python file
# -----------------------------------------

# # Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import soniccli_consts as sc
import datetime
import time
import paramiko
import re


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


def _parse_ssh_result(ssh_text):
    if ssh_text.index(sc.SCLI_SSH_MARK_SUCC) >= 0:
        return True
    if ssh_text.index(sc.SCLI_SSH_MARK_ERR) >= 0:
        return False
    return None


def _ssh_cmd_block_addr(addr, zone):
    cmd_list_1 = []
    cmd1 = cmd2 = ''
    if zone == 'WAN':
        cmd1 = 'access-rule from LAN to WAN action deny' \
            + ' destination address name %s' % addr
        cmd2 = 'access-rule from WAN to LAN action deny' \
            + ' source address name %s' % addr
        cmd_list_1 = [
            'show access-rule from LAN to WAN action deny' +
            ' destination address name %s' % addr,
            'show access-rule from WAN to LAN action deny' +
            ' source address name %s' % addr
        ]
    else:
        cmd1 = 'access-rule from %s to WAN action deny' % zone \
            + ' source address name %s' % addr
        cmd2 = 'access-rule from WAN to %s action deny' % zone \
            + ' destination address name %s' % addr
        cmd_list_1 = [
            'show access-rule from %s to WAN action deny' % zone +
            ' source address name %s' % addr,
            'show access-rule from WAN to %s action deny' % zone +
            ' destination address name %s' % addr,
        ]

    comment = 'comment "%s"' % sc.SCLI_ACL_COMMENT
    cmd_list_2 = [
        "configure", cmd1, comment, "exit",
        cmd2, comment, "exit",
        "commit", " ", "exit",
    ]
    return (cmd_list_1, cmd_list_2)


def _ssh_cmd_unblock_addr(addr, zone):
    cmd_list_1 = []
    cmd1 = cmd2 = ''
    if zone == 'WAN':
        cmd1 = 'no access-rule from LAN to WAN action deny' \
            + '  destination address name %s' % addr
        cmd2 = 'no access-rule from WAN to LAN action deny' \
            + '  source address name %s' % addr
        cmd_list_1 = [
            'show access-rule from LAN to WAN action deny' +
            '  destination address name %s' % addr,
            'show access-rule from WAN to LAN action deny' +
            '  source address name %s' % addr
        ]
    else:
        cmd1 = 'no access-rule from %s to WAN action deny' % zone \
            + '  source address name %s' % addr
        cmd2 = 'no access-rule from WAN to %s action deny' % zone \
            + '  destination address name %s' % addr
        cmd_list_1 = [
            'show access-rule from %s to WAN action deny' % zone +
            '  source address name %s' % addr,
            'show access-rule from WAN to %s action deny' % zone +
            '  destination address name %s' % addr,
        ]

    cmd_list_2 = [
        "configure", cmd1, cmd2,
        "commit", " ", "exit",
    ]
    return (cmd_list_1, cmd_list_2)


def _ssh_cmd_block_service(protocol, port, portend=0):
    if portend == 0:
        portend = port
    cmd1 = 'access-rule from LAN to WAN action deny' \
        + '  service protocol %s %d %d' % (protocol, port, portend)
    cmd2 = 'access-rule from WAN to LAN action deny' \
        + '  service protocol %s %d %d' % (protocol, port, portend)
    cmd_list_1 = [
        'show access-rule from LAN to WAN action deny' +
        '  service protocol %s %d %d' % (protocol, port, portend),
        'show access-rule from WAN to LAN action deny' +
        '  service protocol %s %d %d' % (protocol, port, portend)
    ]
    comment = 'comment "%s"' % sc.SCLI_ACL_COMMENT
    cmd_list_2 = [
        "configure", cmd1, comment, "exit",
        cmd2, comment, "exit",
        "commit", " ", "exit",
    ]
    return (cmd_list_1, cmd_list_2)


def _ssh_cmd_unblock_service(protocol, port, portend=0):
    if portend == 0:
        portend = port
    cmd1 = 'no access-rule from LAN to WAN action deny' \
        + '  service protocol %s %d %d' % (protocol, port, portend)
    cmd2 = 'no access-rule from WAN to LAN action deny' \
        + '  service protocol %s %d %d' % (protocol, port, portend)
    cmd_list_1 = [
        'show access-rule from LAN to WAN action deny' +
        '  service protocol %s %d %d' % (protocol, port, portend),
        'show access-rule from WAN to LAN action deny' +
        '  service protocol %s %d %d' % (protocol, port, portend),
    ]
    cmd_list_2 = [
        "configure", cmd1, cmd2,
        "commit", " ", "exit",
    ]
    return (cmd_list_1, cmd_list_2)


def _ssh_cmd_add_address(addr, zone):
    addr_type = _tell_address_type(addr)
    cmd1 = 'address-object %s "%s" host %s zone %s' \
        % (addr_type, addr, addr, zone)
    if addr_type == 'fqdn':
        cmd1 = 'address-object fqdn "%s" domain %s zone %s' \
            % (addr, addr, zone)
    cmd2 = 'show address-object %s "%s"' % (addr_type, addr)
    cmd_list_1 = [cmd2, ]
    cmd_list_2 = ["configure", cmd1, "commit", " ", "exit", " "]
    return (cmd_list_1, cmd_list_2)


def run_cmd(host, user, pwd, *cmds):
    cmd = []
    for x in cmds:
        if isinstance(x, list):
            cmd = cmd + x
        elif isinstance(x, str):
            cmd.append(x)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=pwd, timeout=15)

    trans = client.get_transport()
    chans = trans.open_channel('session')
    chans.settimeout(5)
    chans.get_pty('vt100', 80, 240, 320, 960)
    chans.invoke_shell()

    cmd_list = cmd
    if not isinstance(cmd, list):
        cmd_list = [cmd]

    resp_list = []
    _strs = chans.recv(1000)
    print _strs
    for _cmd in cmd_list:
        strs = ''
        _strs = ''
        print "Run command: " + _cmd
        chans.send(_cmd + '\n')
        for x in range(10):
            print "Wait response"
            time.sleep(0.5)
            _strs = chans.recv(1000)
            print _strs
            if _strs:
                break
        strs = strs + _strs + '\n'

        react = ssh_expect(_strs)
        while react is not None:
            chans.send(react)
            time.sleep(0.5)
            _strs = chans.recv(1000)
            strs = strs + _strs
            print _strs
            react = ssh_expect(_strs)
        resp_list.append(strs)

    client.close()
    return resp_list


def get_address_zone(host, user, pwd, addr):

    type = _tell_address_type(addr)
    result = {'succeed': False, 'error': '', 'zone': ''}

    ip_addr = addr
    if type == 'fqdn':
        ip_addr = ''
        _resp = run_cmd(host, user, pwd, 'nslookup ' + addr)
        if 'Resolved Address:' in _resp[0]:
            print "searching resolved address"
            m = re.findall(
                r'Resolved Address:\s*(\d+\.\d+\.\d+\.\d+)', _resp[0])
            if m:
                print m
                ip_addr = m[0]
            else:
                result['error'] = 'URL %s not resolved' % addr
                return result
        elif 'Failure resolving' in _resp[0]:
            result['error'] = 'Check DNS server and network.'
            return result

        if not ip_addr:
            lines = _resp[0].split('\n')
            ipp = re.compile(r'\d+\.\d+\.\d+\.\d+')
            for aline in lines:
                if addr not in aline:
                    continue
                m = ipp.findall(aline)
                if m:
                    ip_addr = m[0]
                    print "Found address " + ip_addr
                    break

        if not ip_addr:
            result['error'] = 'URL %s not resolved' % addr
            return result

    cmd_list = ['show status', 'network-path ' + ip_addr, 'show interfaces']
    _resp = run_cmd(host, user, pwd, cmd_list)

    status_blocks = _resp[0].split('Network Interfaces')
    if len(status_blocks) < 2:
        result['error'] = 'Network interface not found'
        return result
    status_lines = status_blocks[1].split('\n')

    match_np = re.findall(r'is located on the ([UX]\d)', _resp[1])
    if match_np:
        ip_if = match_np[0]
        print "Found addr is located on interface >>%s<<" % ip_if
        ifp = re.compile(ip_if + r'\((.*)\)')
        for aline in status_lines:
            m = ifp.findall(aline)
            if m:
                print aline
                print "Found ip addr in zone %s" % m[0]
                result['succeed'] = True
                result['zone'] = m[0]
                return result

    result['succeed'] = True
    result['zone'] = match_if_network(_resp[2], ip_addr)
    return result


def ssh_expect(resp):
    if 'yes/no' in resp:
        return 'yes\n'
    if '--MORE--' in resp:
        return ' '
    if len(resp) > 1:
        return ' '
    return None


def exaime_ssh_error(resp_list):
    e_list = []
    for resp in resp_list:
        lns = resp.split('\n')
        for ln in range(len(lns)):
            if '% Error encountered' in lns[ln] and len(lns) >= ln + 3:
                if lns[ln + 3] not in e_list:
                    e_list.append(lns[ln + 3])
    return e_list


def find_address_object_host(str, host, type, zone):
    wanted_line = ''
    if type == 'ipv4':
        wanted_line = 'address-object ipv4 %s host %s zone %s' \
            % (host, host, zone)
    elif type == 'fqdn':
        wanted_line = 'address-object fqdn %s domain %s zone %s' \
            % (host, host, zone)
    else:
        wanted_line = 'address-object %s %s ' % (type, host)
        return None
    print "Search this: " + wanted_line
    if wanted_line in str:
        return host
    return None


def ip_hex(ip):
    return sum([256 ** j * int(i) for j, i in enumerate(ip.split('.')[::-1])])


def match_if_network(str, ip):
    ifs = str.split('interface ')
    nip = ip_hex(ip)
    hasip = re.compile(r'\d+\.\d+\.\d+\.\d+')

    for i in range(len(ifs)):
        if i == 0:
            continue
        if_str = ifs[i]
        lines = if_str.split('\n')

        line1_items = lines[1].strip().split()
        line2_items = lines[2].strip().split()
        if len(line2_items) < 3:
            continue
        if_zone = line1_items[1]
        if_ip = line2_items[1]
        if_mask = line2_items[3]
        if hasip.match(if_ip) and hasip.match(if_mask):
            if ip_hex(if_ip) & ip_hex(if_mask) == nip & ip_hex(if_mask):
                return if_zone

    return 'WAN'


def find_access_rule(str, user_exclude=None):
    if user_exclude is None:
        if "No matching command found" in str:
            return False
        if "Access Rule not found" in str:
            return False
        return True


def _tell_address_type(target_addr):
    if re.match(r'\d+\.\d+\.\d+\.\d+', target_addr):
        return 'ipv4'
    elif ':' in target_addr:
        return 'ipv6'
    else:
        return 'fqdn'


def _tell_user_type(target_user):
    return 'local'


class Soniccli_Connector(BaseConnector):

    ACTION_ID_BLOCK_IP = "block_ip"
    ACTION_ID_BLOCK_URL = "block_url"
    ACTION_ID_UNBLOCK_IP = "unblock_ip"
    ACTION_ID_UNBLOCK_URL = "unblock_url"
    ACTION_ID_BLOCK_USER = "block_user"
    ACTION_ID_UNBLOCK_USER = "unblock_user"
    ACTION_ID_BLOCK_SERV = "block_service"
    ACTION_ID_UNBLOCK_SERV = "unblock_service"
    ACTION_ID_LIST_SERV = "list_service"

    BLOCKED_IP_GROUP = 'blocked_ips'
    BLOCKED_USER_GROUP = 'blocked_users'

    action_message = ''

    def _append_log(self, message):
        self.action_message = self.action_message + message + '. '

    def _action_block_addr(self, fwip, user, pwd, target_addr):
        output_list = []
        address_zone = get_address_zone(fwip, user, pwd, target_addr)
        if address_zone['succeed'] is not True:
            self._append_log(address_zone['error'])
            return False
        zone = address_zone['zone']
        (query_cmd_list, operate_cmd_list) = \
            _ssh_cmd_block_addr(target_addr, zone)

        (q_ao_cmd, a_ao_cmd) = _ssh_cmd_add_address(target_addr, zone)
        try:
            output_list = run_cmd(fwip, user, pwd, a_ao_cmd)
        except Exception as e:
            self._append_log("SSH Error: " + e.message)
            return False
        error_line = exaime_ssh_error(output_list)
        if error_line:
            self._append_log("Command Failed" + ''.join(error_line))
            return False

        try:
            output_list = run_cmd(fwip, user, pwd, operate_cmd_list)
        except Exception as e:
            self._append_log("SSH Error: " + e.message)
            return False
        error_line = exaime_ssh_error(output_list)
        if error_line:
            self._append_log("Command Failed" + ''.join(error_line))
            return False
        return True

    def _action_unblock_addr(self, fwip, user, pwd, target_addr):
        output_list = []
        address_zone = get_address_zone(fwip, user, pwd, target_addr)
        if address_zone['succeed'] is not True:
            self._append_log(address_zone['error'])
            return False
        zone = address_zone['zone']
        (query_cmd_list, operate_cmd_list) = \
            _ssh_cmd_unblock_addr(target_addr, zone)

        try:
            output_list = run_cmd(fwip, user, pwd, operate_cmd_list)
        except Exception as e:
            self._append_log("SSH Error: " + e.message)
            return False
        error_line = exaime_ssh_error(output_list)
        for anerror in error_line:
            if 'No matching command found' in anerror:
                pass
            elif 'Parameter not found' in anerror:
                pass
            else:
                self._append_log("Command Failed. " + ''.join(error_line))
                return False
        return True

    def _action_block_service(self, fwip, user, pwd, pcol, port, porte=0):
        output_list = []
        (query_cmd_list, operate_cmd_list) = \
            _ssh_cmd_block_service(pcol, port, porte)

        try:
            output_list = run_cmd(fwip, user, pwd, operate_cmd_list)
        except Exception as e:
            self._append_log("SSH Error: " + e.message)
            return False
        error_line = exaime_ssh_error(output_list)
        if error_line:
            self._append_log("Command Failed. " + ''.join(error_line))
            return False

        return True

    def _action_unblock_service(self, fwip, user, pwd, pcol, port, porte=0):
        output_list = []
        (query_cmd_list, operate_cmd_list) = \
            _ssh_cmd_unblock_service(pcol, port, porte)

        try:
            output_list = run_cmd(fwip, user, pwd, operate_cmd_list)
        except Exception as e:
            self._append_log("SSH Error: " + e.message)
            return False
        error_line = exaime_ssh_error(output_list)
        for anerror in error_line:
            if 'Parameter not found' in anerror:
                pass
            else:
                self._append_log("Command Failed. " + ''.join(error_line))
                return False
        return True

    def _test_connectivity(self, param):
        config = self.get_config()

        firewall = config.get(sc.SCLI_JSON_FW)
        username = config.get(sc.SCLI_JSON_USER)
        password = config.get(sc.SCLI_JSON_PWD)

        if not firewall or not username or not password:
            self.save_progress("Firewall is not set")
            return self.get_status()

        self.save_progress("Querying a single server to check connectivity")

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, firewall)

        try:
            return_str = run_cmd(firewall, username, password, "show version")
            for x in return_str:
                self.save_progress(x)
            if not return_str:
                self.set_status(phantom.APP_ERROR, sc.SCLI_CONN_TEST_ERR)
                self.append_to_message(sc.SCLI_CONN_TEST_ERR)
        except Exception as e:
            self.set_status(phantom.APP_ERROR, sc.SCLI_CONN_TEST_ERR, e)
            self.append_to_message(sc.SCLI_CONN_TEST_ERR)
            return self.get_status()

        return self.set_status_save_progress(
            phantom.APP_SUCCESS, sc.SCLI_CONN_TEST_SUCC)

    def _handle_cmd(self, param):
        config = self.get_config()

        self.debug_print("param", param)

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        firewall = config.get(sc.SCLI_JSON_FW)
        username = config.get(sc.SCLI_JSON_USER)
        password = config.get(sc.SCLI_JSON_PWD)

        action_id = self.get_action_identifier()

        cmd_result = False
        output_data = {}
        if action_id == self.ACTION_ID_BLOCK_IP:
            target_info = param[sc.SCLI_JSON_TARGET]
            cmd_result = self._action_block_addr(
                firewall, username, password, target_info)
            output_data = {'operate_address': param[sc.SCLI_JSON_TARGET], }
        elif action_id == self.ACTION_ID_BLOCK_URL:
            target_info = param[sc.SCLI_JSON_TARGET]
            cmd_result = self._action_block_addr(
                firewall, username, password, target_info)
            output_data = {'operate_address': param[sc.SCLI_JSON_TARGET], }

        elif action_id == self.ACTION_ID_UNBLOCK_IP:
            target_info = param[sc.SCLI_JSON_TARGET]
            cmd_result = self._action_unblock_addr(
                firewall, username, password, target_info)
            output_data = {'operate_address': param[sc.SCLI_JSON_TARGET], }
        elif action_id == self.ACTION_ID_UNBLOCK_URL:
            target_info = param[sc.SCLI_JSON_TARGET]
            cmd_result = self._action_unblock_addr(
                firewall, username, password, target_info)
            output_data = {'operate_address': param[sc.SCLI_JSON_TARGET], }

        elif action_id == self.ACTION_ID_BLOCK_SERV:
            protocol = param[sc.SCLI_JSON_PROTOCOL]
            port = int(param[sc.SCLI_JSON_PORT])
            port_end = port
            if sc.SCLI_JSON_PORTEND in param:
                port_end = int(param[sc.SCLI_JSON_PORTEND])
            cmd_result = self._action_block_service(
                firewall, username, password, protocol, port, port_end)
            output_data = {
                'protocol': protocol,
                'port_start': port,
                'port_end': port_end}

        elif action_id == self.ACTION_ID_UNBLOCK_SERV:
            protocol = param[sc.SCLI_JSON_PROTOCOL]
            port = int(param[sc.SCLI_JSON_PORT])
            port_end = port
            if sc.SCLI_JSON_PORTEND in param:
                port_end = int(param[sc.SCLI_JSON_PORTEND])
            cmd_result = self._action_unblock_service(
                firewall, username, password, protocol, port, port_end)
            output_data = {
                'protocol': protocol,
                'port_start': port,
                'port_end': port_end}

        if cmd_result is True:
            action_result.set_status(phantom.APP_SUCCESS)
            action_result.append_to_message('Operation succeed')
        else:
            action_result.set_status(phantom.APP_ERROR)
            action_result.append_to_message('Operation failed')

        action_result.append_to_message(self.action_message)
        action_result.add_data(output_data)
        summary = {'firewall': firewall, 'operation': action_id}
        action_result.update_summary(summary)
        return action_result.get_status()

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.action_message = ''

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        else:
            ret_val = self._handle_cmd(param)

        return ret_val

if __name__ == '__main__':

    import json
    import sys
    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))

        connector = Soniccli_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
