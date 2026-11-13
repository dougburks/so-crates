#!/usr/bin/env python3
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import db
import findings


def _record(event_type, body, n=0, **top):
    event = {'event_type': event_type, 'timestamp': f'2026-01-01T00:00:{n:02d}.000000+0000',
             'src_ip': '10.0.0.5', 'src_port': 40000 + n, 'dest_ip': '10.0.0.9', 'dest_port': 1000 + n,
             'proto': 'UDP', 'source': 'tshark', event_type: body}
    event.update(top)
    return event


# A record each rule matches, by rule id - shaped as shark_protocols.py
# writes them
MATCHES = {
    'ipmi_cipher_zero': ('ipmi', {'requested_privilege': 'administrator', 'weaknesses': ['cipher zero accepted']}),
    'ipmi_anonymous': ('ipmi', {'weaknesses': ['anonymous login']}),
    'ipmi_weak_auth': ('ipmi', {'weaknesses': ['cleartext password']}),
    'opcua_cleartext_password': ('opcua', {'username': 'user1', 'password': 'hunter2',
                                           'endpoint': 'opc.tcp://plc:4840/'}),
    'telnet_login': ('telnet', {'banner': 'MOXA', 'username': 'admin', 'password': 'moxa-secret',
                                'login': 'failed'}),
    'rsh_login': ('rsh', {'service': 'rexec', 'user': 'operator', 'password': 'rexec-secret',
                           'command': 'shutdown -r now', 'result': 'refused'}),
    's7_plc_control': ('s7comm', {'function': 'PLC Stop'}),
    's7_download': ('s7comm', {'function': 'Download block'}),
    'bacnet_device_control': ('bacnet', {'service': 'reinitializeDevice', 'state': 'coldstart',
                                         'password': 'bacnet-secret', 'result': 'ok'}),
    'goose_anomaly': ('goose', {'anomaly': 'stNum skipped 4', 'stnum_gap': 4}),
    'mms_control': ('mms_action', {'service': 'write', 'object': 'IED1LD0/XCBR1$CO$Pos$Oper', 'control': 'operate',
                                   'value': '1, 0', 'result': 'success'}),
    'mongodb_destroy': ('mongodb_action', {'command': 'dropDatabase', 'database': 'shop', 'result': 'ok'}),
    'mongodb_user_change': ('mongodb_action', {'command': 'createUser', 'database': 'admin', 'user': 'backdoor',
                                               'roles': ['role: root, db: admin'], 'result': 'ok'}),
    'pn_dcp_set': ('pn_dcp', {'service': 'Set', 'changes': ['IP address'], 'ip': '192.168.0.10', 'result': 'ok'}),
    'slp_registration': ('slp', {'function': 'Service Registration', 'status': 'OK',
                                 'url': 'service:printer:lpr://198.51.100.14'}),
    's7_write': ('s7comm', {'function': 'Write Var', 'response': {'item_count': 1}}),
    'iec104_control': ('iec104', {'action': 'Single command', 'ioa': 2, 'result': 'confirmed'}),
    'opcua_change': ('opcua_action', {'service': 'Write', 'node': 'ns=1;s=x', 'result': 'Good'}),
    'mms_change': ('mms_action', {'service': 'write', 'object': 'mu', 'value': '0', 'result': 'success'}),
    'mongodb_unauthenticated': ('mongodb', {'commands': {'isMaster': 1, 'listDatabases': 1}, 'unauthenticated': True,
                                           'driver': 'PyMongo 4.6.3'}),
    'mongodb_change': ('mongodb_action', {'command': 'insert', 'database': 'READ_ME', 'collection': 'README', 'count': 1,
                                          'result': 'ok'}),
    'openvpn_tunnel': ('openvpn', {'stage': 'established', 'certificate': {'subject': 'CN=vpn.example'},
                                   'data_to_server': 2, 'data_to_client': 2}),
    'tacacs_cleartext': ('tacacs', {'type': 'authentication', 'encrypted': False, 'user': 'admin',
                                    'password': 'Sup3rS3cret', 'result': 'Authentication Passed'}),
    'ecat_firmware': ('ecat', {'foe': ['write firmware.efw'], 'eeprom_writes': 1}),
    'fins_control': ('fins_action', {'command': 'Stop', 'code': '0x0402', 'result': 'ok'}),
    'hart_ip_process_change': ('hart_ip_action', {'command': 'Enter/Exit Fixed Current Mode', 'number': 40,
                                                  'device': '264e0000d2', 'data': '20 mA', 'result': 'success'}),
    'memcache_amplifier': ('memcache', {'commands': {'stats': 1}, 'answered': True, 'request_bytes': 21,
                                        'response_bytes': 10976, 'amplification': 522.7}),
    'memcache_flush': ('memcache', {'commands': {'flush_all': 1}, 'answered': True}),
    'irc_bot_commands': ('irc', {'nick': 'USA|83621', 'login': 'registered', 'channels': ['#ddos'],
                                 'bot_commands': ['!ddos.syn 203.0.113.50 80 120']}),
    'zabbix_remote_command': ('zabbix', {'request': 'passive check', 'connections': 1, 'commands': [
        {'command': 'id', 'via': 'system.run', 'result': 'uid=0(root)'}]}),
    'redis_replication': ('redis_command', {'command': 'REPLICAOF 10.66.66.66 21000', 'name': 'REPLICAOF',
                                            'master': '10.66.66.66:21000', 'result': 'ok', 'count': 1}),
    'redis_module_load': ('redis_command', {'command': 'MODULE LOAD /tmp/exp.so', 'name': 'MODULE LOAD',
                                            'module': '/tmp/exp.so', 'result': 'ok', 'count': 1}),
    'redis_file_write': ('redis_command', {'command': 'CONFIG SET dir /root/.ssh', 'name': 'CONFIG SET',
                                           'settings': ['dir'], 'result': 'ok', 'count': 1}),
    'redis_account_change': ('redis_command', {'command': 'ACL SETUSER b on >*** ~* +@all', 'name': 'ACL SETUSER',
                                               'password': 'hunter2', 'result': 'ok', 'count': 1}),
    'redis_destroy': ('redis_command', {'command': 'FLUSHALL', 'name': 'FLUSHALL', 'result': 'ok', 'count': 1}),
    'mssql_os_command': ('mssql_statement', {'statement': "EXEC xp_cmdshell 'whoami'", 'verb': 'EXEC', 'result': 'ok'}),
    'mssql_cleartext_login': ('mssql', {'encryption': 'none', 'user': 'sa', 'password': 'x', 'login': 'succeeded'}),
    'mssql_account_change': ('mssql_statement', {'statement': 'ALTER SERVER ROLE sysadmin ADD MEMBER b',
                                                 'verb': 'ALTER SERVER ROLE', 'result': 'ok'}),
    'mssql_destroy': ('mssql_statement', {'statement': 'DROP DATABASE shop', 'verb': 'DROP DATABASE', 'result': 'ok'}),
    'mysql_file_access': ('mysql_statement', {'statement': "SELECT '<?php ?>' INTO OUTFILE '/var/www/html/s.php'",
                                              'verb': 'SELECT', 'result': 'ok'}),
    'mysql_account_change': ('mysql_statement', {'statement': "GRANT ALL ON *.* TO 'b'@'%'", 'verb': 'GRANT', 'result': 'ok'}),
    'mysql_destroy': ('mysql_statement', {'statement': 'DROP DATABASE shop', 'verb': 'DROP DATABASE', 'result': 'ok'}),
    'tns_account_change': ('tns_statement', {'statement': 'grant dba to backdoor', 'verb': 'GRANT', 'result': 'ok'}),
    'tns_destroy': ('tns_statement', {'statement': 'drop table audit_log', 'verb': 'DROP TABLE', 'result': 'ok'}),
    'wireguard_tunnel': ('wireguard', {'stage': 'established', 'data_to_server': 2, 'data_to_client': 2}),
    'fins_change': ('fins_action', {'command': 'Memory Area Write', 'area': 'DM : Word contents', 'address': '0x0064',
                                    'result': 'ok'}),
    'hart_ip_change': ('hart_ip_action', {'command': 'Write Tag, Descriptor, Date', 'number': 18, 'result': 'success'}),
    'synphasor_data_off': ('synphasor', {'commands': {'data transmission off': 1}, 'stations': ['Substation B PMU'],
                                         'stream_id': 1410}),
    'mssql_configuration': ('mssql_statement', {'statement': "EXEC sp_configure 'xp_cmdshell', 1", 'verb': 'EXEC',
                                                'result': 'ok'}),
    'mssql_password_hashes': ('mssql_statement', {'statement': 'SELECT name, password_hash FROM sys.sql_logins',
                                                  'verb': 'SELECT', 'result': 'ok'}),
    'mssql_change': ('mssql_statement', {'statement': 'UPDATE t SET a = 1', 'verb': 'UPDATE', 'result': 'ok'}),
    'irc_bot_nick': ('irc', {'nick': '[DEU|W10]48213', 'login': 'registered', 'bot_like_nick': True,
                             'server': 'irc.alt.example'}),
    'irc_dcc_send': ('irc', {'nick': 'USA|83621', 'dcc': [{'file': 'loot.zip', 'address': '198.51.100.66:5050',
                                                          'from': 'USA|83621', 'to': 'herder'}]}),
    'zabbix_file_read': ('zabbix', {'request': 'active checks', 'host': 'web01',
                                    'keys': ['system.uptime', 'vfs.file.contents[/etc/shadow]']}),
    'zabbix_credentials': ('zabbix', {'request': 'proxy config', 'host': 'Proxy1',
                                      'credentials': {'ipmi_password': 1, 'tls_psk': 2}}),
    'redis_scripts': ('redis_command', {'command': 'EVAL "return 1" 0', 'name': 'EVAL', 'result': '1', 'count': 1}),
    'redis_no_auth': ('redis', {'commands': {'KEYS': 1}, 'auth': 'none', 'server': 'redis', 'server_version': '7.2.4'}),
    'redis_config_change': ('redis_command', {'command': 'CONFIG SET protected-mode no', 'name': 'CONFIG SET',
                                              'settings': ['protected-mode'], 'result': 'ok', 'count': 1}),
    'mysql_password_hashes': ('mysql_statement', {'statement': 'SELECT user, password FROM mysql.user', 'verb': 'SELECT',
                                                  'result': 'ok'}),
    'mysql_no_password': ('mysql', {'user': 'root', 'login': 'succeeded', 'password_sent': False}),
    'mysql_change': ('mysql_statement', {'statement': 'INSERT INTO t VALUES (1)', 'verb': 'INSERT', 'result': 'ok'}),
    'tns_change': ('tns_statement', {'statement': 'insert into payroll values (1)', 'verb': 'INSERT', 'result': 'ok'}),
    'tns_listener_command': ('tns', {'command': 'status', 'result': 'accepted'}),
    'ecat_state_change': ('ecat', {'state_requests': {'INIT': 1}, 'broadcast_state_change': True}),
    'socks_open': ('socks', {'auth_method': 'no authentication', 'status': 'succeeded',
                             'request_name': 'files.example.net', 'request_port': 80}),
    'xdmcp_offered': ('xdmcp', {'result': 'willing', 'server_host_name': 'labsrv'}),
    'rip_default_route': ('rip', {'command': 'response', 'routes': ['10.2.0.0/16 metric 1', '0.0.0.0/0 metric 1']}),
    'rip_cleartext_password': ('rip', {'authentication': 'simple password', 'route_count': 3}),
    'tunnel_return': ('tunnel', {'type': 'IP-in-IP', 'returns_to_sender': True}),
    'rpc_exports': ('rpc', {'exports': ['/srv/nfs']}),
    'syslog_critical': ('syslog', {'severity': 'crit', 'hostname': 'fw01', 'message': 'disk failing'}),
    'pn_dcp_identify_all': ('pn_dcp', {'service': 'Identify', 'query': 'all', 'count': 1, 'responses': 3}),
    'openvpn_retries': ('openvpn', {'stage': 'client reset only', 'client_resets': 5}),
    'wireguard_retries': ('wireguard', {'stage': 'initiation only', 'initiations': 4}),
    'fins_identified': ('fins', {'model': 'CJ2M-CPU31', 'version': '02.01', 'answered': True}),
    'hart_ip_session': ('hart_ip', {'session': 'accepted', 'host_type': 'primary master', 'tags': ['PT-101']}),
    'memcache_stats': ('memcache', {'commands': {'stats': 1}, 'stats': ['stats items'], 'answered': True,
                                    'version': '1.6.38'}),
    'synphasor_not_synced': ('synphasor', {'not_synced': 3, 'stations': ['Substation B PMU']}),
    'synphasor_config_read': ('synphasor', {'pmus': [{'station': 'Substation B PMU'}], 'stations': ['Substation B PMU'],
                                            'stream_id': 1410}),
    'tacacs_login_failed': ('tacacs', {'type': 'authentication', 'encrypted': False, 'user': 'guest',
                                       'result': 'Authentication Failed'}),
    'tacacs_command_refused': ('tacacs', {'type': 'authorization', 'encrypted': False, 'user': 'admin',
                                          'command': 'write erase', 'result': 'FAIL'}),
    'raknet_server': ('raknet', {'answered': True, 'advertisement': 'MCPE;Lab Server;712;1.21.20;3;10',
                                 'edition': 'MCPE', 'motd': 'Lab Server', 'game_version': '1.21.20', 'players': 3,
                                 'max_players': 10}),
    'ecat_over_ip': ('ecat', {'commands': {'BRD': 1}, 'answered': True, 'slaves': 2}),
    'mssql_login_failed': ('mssql', {'user': 'sa', 'login': 'failed', 'login_error': 'Error 18456'}),
    'irc_connection': ('irc', {'nick': 'alice', 'login': 'registered', 'network': 'Libera.Chat',
                               'channels': ['#python']}),
    'irc_password': ('irc', {'nick': 'herder', 'login': 'failed', 'password': 'hunter2',
                             'channel_keys': {'#ddos': 'hunter2'}}),
    'redis_login_failed': ('redis', {'user': 'default', 'password': 'hunter2', 'auth': 'failed', 'login_failures': 2}),
    'zabbix_refused': ('zabbix', {'request': 'passive check', 'not_supported': 2, 'errors': ['Unsupported item key.']}),
    'mysql_login_failed': ('mysql', {'user': 'app', 'login': 'failed', 'login_error': 'ERROR 1045: Access denied'}),
    'tns_login_failed': ('tns', {'db_user': 'system', 'login': 'failed', 'login_error': 'ORA-01017: invalid'}),
    'tns_unknown_service': ('tns', {'sid': 'ORCLX', 'result': 'refused', 'error': 'ORA-12505'}),
    'rsh_answering': ('rsh', {'service': 'rsh', 'probe': 'GET / HTTP/1.0', 'result': 'refused',
                              'error': 'Can not make pipe'}),
    'rip_whole_table': ('rip', {'command': 'request', 'whole_table': True, 'responses': 1, 'route_count': 2}),
    'rpc_portmapper': ('rpc', {'mappings': [{'program': 'nfs'}, {'program': 'mountd'}]}),
    'bacnet_write': ('bacnet', {'service': 'writeProperty', 'object': 'analog-value,0', 'result': 'ok'}),
    'slp_answered': ('slp', {'function': 'Service Request', 'response': 'Service Reply', 'status': 'OK'}),
    'knxip_programming': ('knxip', {'services': {'Tunnelling Request': 3}, 'status': 'accepted',
                                    'management': ['Master_Reset 1.1.5', 'GroupValue_Write 1/2/3'],
                                    'programming': ['Master_Reset']}),
    'knxip_open_connection': ('knxip', {'connection_type': 'tunnel', 'status': 'accepted', 'tunnel_address': '1.1.250',
                                        'group_writes': {'1/2/3': 1}}),
    'knxip_described': ('knxip', {'services': {'Description Request': 1, 'Description Response': 1},
                                  'device': {'name': 'Office IP Interface', 'individual_address': '1.1.250',
                                             'serial': '00:c5:01:02:03:ff'}}),
    'wsd_probe': ('wsd', {'message': 'invalid', 'payload': '<:>', 'request_bytes': 3, 'answered': False}),
    'wsd_reflector': ('wsd', {'message': 'invalid', 'payload': '<:>', 'request_bytes': 3, 'response': 'Fault',
                              'response_bytes': 441, 'answered': True, 'amplification': 147.0}),
    'coap_discovery': ('coap', {'resources': ['/sensors/temp']}),
    'l2tp_no_auth': ('l2tp', {'state': 'established', 'client_host_name': 'WIN-CLIENT7'}),
    'radius_reject': ('radius', {'result': 'rejected', 'user': 'bob', 'nas_ip': '10.1.0.2'}),
    'tls_certificate_refused': ('tls_failure', {'alert': 'Handshake Failure', 'sent_by': 'server',
                                                'alerts': ['server: Handshake Failure', 'client: Unknown CA'],
                                                'sni': 'vpn.example', 'subject': 'CN=vpn.example'}),
    'tls_certificate_out_of_date': ('tls', {'sni': 'old.example', 'subject': 'CN=old.example', 'issuerdn': 'CN=Some CA',
                                            'notbefore': '2024-01-01T00:00:00', 'notafter': '2025-06-01T00:00:00'}),
    'tls_self_signed': ('tls', {'sni': 'lab.example', 'subject': 'CN=lab.example', 'issuerdn': 'CN=lab.example',
                                'notbefore': '2025-01-01T00:00:00', 'notafter': '2027-01-01T00:00:00'}),
    'tls_name_mismatch': ('tls', {'sni': 'login.bank.example', 'subject': 'CN=*.cdn.example', 'issuerdn': 'CN=Some CA',
                                  'subjectaltname': ['*.cdn.example', 'cdn.example']}),
    'tls_compromised_ca': ('tls', {'sni': 'login.bank.example', 'subject': 'CN=login.bank.example',
                                   'issuerdn': 'C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B',
                                   'subjectaltname': ['login.bank.example']}),
}

# Records like those the rules look for that no rule should match
NON_MATCHES = [
    ('ipmi', {'weaknesses': []}),
    ('ipmi', {'result': 'answered'}),
    ('opcua', {'username': 'user1', 'password_encrypted': True}),
    ('telnet', {'banner': 'MOXA'}),
    ('telnet', {'banner': 'MOXA', 'username': '', 'password': ''}),
    ('s7comm', {'function': 'Read Var'}),
    ('bacnet', {'service': 'readProperty'}),
    ('goose', {'changed': ['a']}),
    ('pn_dcp', {'service': 'Set', 'changes': ['signal'], 'result': 'ok'}),
    ('mongodb', {'commands': {'isMaster': 1}, 'answered': False}),
    ('rsh', {'service': 'rsh', 'probe': 'GET / HTTP/1.0', 'result': 'no response'}),
    ('openvpn', {'stage': 'client reset only', 'client_resets': 1}),
    ('openvpn', {'stage': 'server answered', 'client_resets': 3}),
    ('wireguard', {'stage': 'initiation only', 'initiations': 1}),
    ('tns_statement', {'statement': 'SELECT * FROM payroll', 'verb': 'SELECT'}),
    ('tns_statement', {'statement': 'alter session set nls_date_format = x', 'verb': 'ALTER SESSION'}),
    ('tns', {'command': 'ping', 'result': 'answered'}),
    ('tns', {'sid': 'ORCL', 'result': 'refused', 'error': 'ORA-12519'}),
    ('tns', {'db_user': 'scott', 'login': 'succeeded'}),
    ('memcache', {'commands': {'stats': 1}, 'stats': ['stats'], 'answered': False}),
    ('memcache', {'commands': {'get': 1, 'set': 1}, 'answered': True}),
    ('fins', {'commands': {'Controller Data Read': 1}, 'answered': False}),
    ('hart_ip', {'session': 'requested', 'answered': False}),
    ('raknet', {'messages': {'Unconnected Ping': 1}, 'answered': False}),
    ('tacacs', {'type': 'authentication', 'encrypted': True, 'answered': True}),
    ('synphasor', {'commands': {'data transmission on': 1}, 'not_synced': 0}),
    ('ecat', {'commands': {'BRD': 1}, 'answered': False, 'foe': ['read config.xml']}),
    ('mysql', {'user': 'app', 'login': 'succeeded', 'password_sent': True}),
    ('redis', {'commands': {'AUTH': 1, 'GET': 3}, 'user': 'default', 'auth': 'succeeded'}),
    ('redis', {'commands': {'PING': 1}, 'auth': 'required'}),
    ('irc', {'nick': 'alice', 'login': 'not registered', 'commands': {'NICK': 1, 'USER': 1},
             'messages': [{'direction': 'sent', 'to': '#python', 'text': '!help'}]}),
    ('redis_command', {'command': 'CONFIG GET dir', 'name': 'CONFIG GET', 'result': '2 items', 'count': 1}),
    ('redis_command', {'command': 'REPLICAOF NO ONE', 'name': 'REPLICAOF', 'result': 'ok', 'count': 1}),
    ('redis_command', {'command': 'SAVE', 'name': 'SAVE', 'result': 'ok', 'count': 1}),
    ('zabbix', {'request': 'passive check', 'connections': 4, 'keys': ['agent.ping', 'system.uptime']}),
    ('zabbix', {'request': 'proxy config', 'host': 'Proxy1', 'responses': {'success': 1}}),
    ('zabbix', {'request': 'agent data', 'host': 'web01', 'keys': ['vfs.file.contents[/etc/shadow]']}),
    ('mssql', {'encryption': 'login only', 'login': 'succeeded'}),
    ('mssql_statement', {'statement': 'SELECT 1', 'verb': 'SELECT', 'result': 'ok'}),
    ('mssql_statement', {'statement': "EXEC sp_configure", 'verb': 'EXEC', 'result': 'ok'}),
    ('mysql_statement', {'statement': 'SELECT * FROM customers', 'verb': 'SELECT', 'result': 'ok'}),
    ('mysql_statement', {'statement': 'SET NAMES utf8mb4', 'verb': 'SET', 'result': 'ok'}),
    ('wireguard', {'stage': 'handshake', 'initiations': 3, 'handshakes': 3}),
    ('mongodb', {'commands': {'saslStart': 1, 'find': 3}, 'login': 'succeeded'}),
    ('pn_dcp', {'service': 'Identify', 'query': 'switch1', 'count': 2, 'responses': 0}),
    ('slp', {'function': 'Service Registration'}),
    ('wsd', {'message': 'Probe', 'multicast': True, 'request_bytes': 624, 'response': 'ProbeMatches',
             'response_bytes': 3326, 'answered': True}),
    ('wsd', {'message': 'invalid', 'payload': '<:>', 'response_bytes': 441}),
    ('knxip', {'connection_type': 'tunnel', 'status': 'no more connections'}),
    ('knxip', {'status': 'accepted', 'secure': True}),
    ('knxip', {'services': {'Routing Indication': 2}, 'group_writes': {'0/0/1': 1}, 'management': ['DeviceDescriptor_Read 1.1.5']}),
    ('iec104', {'action': 'Interrogation', 'result': 'confirmed, terminated'}),
    ('socks', {'auth_method': 'username/password', 'status': 'succeeded'}),
    ('socks', {'auth_method': 'no authentication', 'status': 'rejected'}),
    ('xdmcp', {'result': 'unwilling'}),
    ('rip', {'command': 'response', 'routes': ['10.0.0.0/8 metric 1', '10.0.0.0/24 metric 2']}),
    ('rip', {'command': 'request', 'whole_table': True}),
    ('tunnel', {'type': 'GRE'}),
    ('syslog', {'severity': 'err'}),
    ('l2tp', {'state': 'established', 'tunnel_authentication': True}),
    ('l2tp', {'state': 'refused'}),
    ('radius', {'result': 'accepted'}),
    ('tls_failure', {'alert': 'Handshake Failure', 'sent_by': 'server', 'alerts': ['server: Handshake Failure']}),
    ('tls', {'sni': 'www.example', 'subject': 'CN=www.example', 'issuerdn': 'CN=Some CA',
             'notbefore': '2025-01-01T00:00:00', 'notafter': '2026-01-02T00:00:00'}),
    ('tls', {'sni': 'www.example', 'version': 'TLS 1.3'}),
    ('tls', {'sni': 'WWW.Shop.example', 'subject': 'CN=shop.example', 'issuerdn': 'CN=Some CA',
             'subjectaltname': ['shop.example', '*.shop.example']}),
    ('tls', {'sni': '192.0.2.7', 'subject': 'CN=device', 'issuerdn': 'CN=Some CA'}),
    # eMudhra's other CAs, a G3 intermediate that isn't one of the eight,
    # and one of the eight's names from someone else
    ('tls', {'sni': 'www.example', 'subject': 'CN=www.example', 'subjectaltname': ['www.example'],
             'issuerdn': 'C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign SSL CA - G1'}),
    ('tls', {'sni': 'www.example', 'subject': 'CN=www.example', 'subjectaltname': ['www.example'],
             'issuerdn': 'C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3'}),
    ('tls', {'sni': 'www.example', 'subject': 'CN=www.example', 'subjectaltname': ['www.example'],
             'issuerdn': 'C=US, O=Example Corp, CN=EM DV TLS CA - G3B'}),
]


class TestFindings(unittest.TestCase):
    def _db(self, events):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        eve = os.path.join(tmp, 'eve.json')
        with open(eve, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        path = os.path.join(tmp, 'events.db')
        db.create_sqlite_db(path, eve)
        return path

    def test_every_rule_has_a_match_here(self):
        self.assertEqual(set(MATCHES), set(findings.RULES_BY_ID))

    def test_rules_are_ordered_most_severe_first(self):
        ranks = [findings.SEVERITIES.index(r.severity) for r in findings.RULES]
        self.assertEqual(ranks, sorted(ranks))

    def test_each_rule_finds_its_record(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(MATCHES.values())]
        result = findings.query_findings(self._db(events))
        found = {}
        for f in result['findings']:
            found.setdefault(f['rule'], []).append(f['event'][f['event']['event_type']])
        for rule, (event_type, body) in MATCHES.items():
            self.assertIn(body, found.get(rule, []), f'{rule} should find its record')

    def test_lookalikes_are_not_findings(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(NON_MATCHES)]
        result = findings.query_findings(self._db(events))
        self.assertEqual(result['findings'], [], [(f['rule'], f['event']) for f in result['findings']])
        self.assertEqual(result['rules'], [])

    def test_no_detail_carries_a_password(self):
        events = [_record(t, b, i) for i, (t, b) in enumerate(MATCHES.values())]
        result = findings.query_findings(self._db(events))
        details = ' '.join(f['detail'] for f in result['findings'])
        for secret in ('hunter2', 'moxa-secret', 'bacnet-secret', 'rexec-secret'):
            self.assertNotIn(secret, details)
        by_rule = {f['rule']: f['detail'] for f in result['findings']}
        self.assertEqual(by_rule['telnet_login'], 'user admin - login failed')
        self.assertEqual(by_rule['opcua_cleartext_password'], 'user user1 on opc.tcp://plc:4840/')
        self.assertEqual(by_rule['rip_default_route'], '0.0.0.0/0 metric 1')
        self.assertEqual(by_rule['s7_write'], '1 item')
        self.assertEqual(by_rule['tls_certificate_refused'], 'client: Unknown CA - CN=vpn.example (for vpn.example)',
                         'the alert that refused the certificate, not the first one')
        self.assertEqual(by_rule['tls_certificate_out_of_date'],
                         'valid 2024-01-01 to 2025-06-01 - CN=old.example (for old.example)')
        self.assertEqual(by_rule['tls_self_signed'], 'CN=lab.example (for lab.example)')
        self.assertEqual(by_rule['tls_name_mismatch'],
                         'asked for login.bank.example - certificate for *.cdn.example, cdn.example')
        tls13 = findings.RULES_BY_ID['tls_certificate_refused'].detail(
            {'alerts': ['client: Unknown CA'], 'sni': 'vpn.example'})
        self.assertEqual(tls13, 'client: Unknown CA (for vpn.example)', 'TLS 1.3: no certificate to name')

    def test_a_missing_value_leaves_no_label_behind(self):
        """A detail's 'to', 'via' or '-' goes with its value when that's
        missing - and a count is pluralized."""
        detail = lambda rule, body: findings.RULES_BY_ID[rule].detail(body)
        self.assertEqual(detail('iec104_control', {'action': 'Single command', 'ioa': 5}), 'Single command to IOA 5')
        self.assertEqual(detail('bacnet_write', {'service': 'writeProperty'}), 'writeProperty')
        self.assertEqual(detail('radius_reject', {'nas_ip': '10.1.0.2'}), 'via 10.1.0.2')
        self.assertEqual(detail('ipmi_cipher_zero', {}), '')
        self.assertEqual(detail('socks_open', {'request_port': 80}), 'to 80')
        self.assertEqual(detail('rip_whole_table', {'route_count': 1}), '1 route')
        self.assertEqual(detail('rpc_portmapper', {'mappings': [{}, {}]}), '2 services')
        self.assertEqual(detail('tls_certificate_refused', {'alerts': ['client: Unknown CA'], 'sni': 'a.example'}),
                         'client: Unknown CA (for a.example)')

    def test_counts_and_order(self):
        events = [_record('bacnet', {'service': 'writeProperty'}, i) for i in range(3)]
        events.append(_record('ipmi', {'weaknesses': ['cipher zero accepted', 'anonymous login']}, 9))
        result = findings.query_findings(self._db(events))
        self.assertEqual([(r['id'], r['count']) for r in result['rules']],
                         [('ipmi_cipher_zero', 1), ('ipmi_anonymous', 1), ('bacnet_write', 3)])
        self.assertEqual([f['rule'] for f in result['findings']],
                         ['ipmi_cipher_zero', 'ipmi_anonymous', 'bacnet_write', 'bacnet_write', 'bacnet_write'])
        self.assertEqual(result['findings'][0]['severity'], 'high')
        self.assertIn('CVE-2013-4782', result['rules'][0]['why'])
        counts = findings.query_findings(self._db(events), counts_only=True)
        self.assertEqual(counts['findings'], [])
        self.assertEqual(sum(r['count'] for r in counts['rules']), 5)

    def test_a_rule_shows_at_most_its_cap(self):
        events = [_record('bacnet', {'service': 'writeProperty'}, i % 60, dest_port=i)
                  for i in range(findings.MAX_PER_RULE + 7)]
        result = findings.query_findings(self._db(events))
        self.assertEqual((result['rules'][0]['count'], result['rules'][0]['groups']),
                         (findings.MAX_PER_RULE + 7, findings.MAX_PER_RULE + 7), 'a server each')
        self.assertEqual(len(result['findings']), findings.MAX_PER_RULE)

    def _certificates(self):
        """One self-signed certificate on one server, fetched 3 times by
        2 clients - and the same certificate on another server."""
        cert = {'sni': 'lab.example', 'subject': 'CN=lab.example', 'issuerdn': 'CN=lab.example'}
        return [_record('tls', cert, 1, src_ip='10.0.0.5', dest_port=443),
                _record('tls', cert, 2, src_ip='10.0.0.6', dest_port=443),
                _record('tls', cert, 3, src_ip='10.0.0.5', dest_port=443),
                _record('tls', cert, 4, dest_ip='10.0.0.10', dest_port=443)]

    def test_the_same_finding_on_the_same_server_is_one_row(self):
        result = findings.query_findings(self._db(self._certificates()))
        self.assertEqual([(r['count'], r['groups']) for r in result['rules']], [(4, 2)])
        rows = [(f['event']['dest_ip'], f['count'], f['sources'], f['first'][:19], f['last'][:19], f['event']['src_port'])
                for f in result['findings']]
        self.assertEqual(rows, [('10.0.0.9', 3, 2, '2026-01-01T00:00:01', '2026-01-01T00:00:03', 40001),
                                ('10.0.0.10', 1, 1, '2026-01-01T00:00:04', '2026-01-01T00:00:04', 40004)],
                         'each with its first record, how many, from how many hosts, and when')
        counts = findings.query_findings(self._db(self._certificates()), counts_only=True)
        self.assertEqual((counts['findings'], counts['rules'][0]['groups']), ([], 2), 'the card counts rows')

    def test_a_rows_own_records(self):
        path = self._db(self._certificates() + [
            _record('tls', {'sni': 'other.example', 'subject': 'CN=other', 'issuerdn': 'CN=other'}, 5, dest_port=443)])
        row = findings.query_findings(path)['findings'][0]
        group = {'rule': row['rule'], 'detail': row['detail'], 'dest_ip': '10.0.0.9', 'dest_port': 443}
        members = findings.query_findings(path, group=group)
        self.assertEqual([f['event']['src_port'] for f in members['findings']], [40001, 40002, 40003],
                         "not the other certificate on that server, nor this one on another")
        self.assertEqual(members['rules'][0]['count'], 3)
        self.assertEqual(findings.query_findings(path, group={**group, 'rule': 'no_such_rule'}), {'rules': [], 'findings': []})
        self.assertEqual(findings.query_findings(path, q=['10.0.0.6'], group=group)['rules'][0]['count'], 1,
                         'a search narrows them too')

    def test_search_narrows_findings(self):
        events = [_record('tunnel', {'type': 'GRE', 'returns_to_sender': True}, 1),
                  _record('tunnel', {'type': 'VXLAN', 'returns_to_sender': True}, 2, dest_ip='192.0.2.77')]
        path = self._db(events)
        result = findings.query_findings(path, q=['192.0.2.77'])
        self.assertEqual([f['event']['tunnel']['type'] for f in result['findings']], ['VXLAN'])
        self.assertEqual(result['rules'][0]['count'], 1)
        self.assertEqual(findings.query_findings(path, q=['nothing-like-this'])['rules'], [])

    def test_a_certificate_is_judged_at_the_time_of_its_connection(self):
        """Not today: a capture from 2015 isn't full of expired
        certificates - nor one made before a certificate's start date
        clean of it. The rule's own column survives a search's FTS join."""
        cert = {'subject': 'CN=a', 'issuerdn': 'CN=CA', 'notbefore': '2015-01-01T00:00:00',
                'notafter': '2016-01-01T00:00:00'}
        events = [_record('tls', cert, 1, timestamp='2015-10-21T10:00:00.000000+0000'),
                  _record('tls', cert, 2, timestamp='2014-12-31T23:59:59.000000+0000'),
                  _record('tls', cert, 3, timestamp='2016-01-01T00:00:01.000000+0000')]
        path = self._db(events)
        found = [f['event']['src_port'] for f in findings.query_findings(path)['findings']]
        self.assertEqual(found, [40002, 40003], 'before it starts and after it ends, not during')
        searched = findings.query_findings(path, q=['CN=CA'])
        self.assertEqual([r['count'] for r in searched['rules']], [2])

    def test_a_certificate_is_judged_in_utc(self):
        """Suricata writes a certificate's dates in UTC but a record's
        time in the server's zone: an hour into a certificate's life is
        within it, however far west the server - and an hour before it
        isn't, however far east. (REGRESSION: compared as text, a server
        at -0400 saw a certificate made 13:16 UTC as not yet valid at
        14:16 UTC, written 10:16-0400.)"""
        cert = {'subject': 'CN=a', 'issuerdn': 'CN=CA', 'notbefore': '2026-10-28T13:16:29',
                'notafter': '2027-12-02T13:16:29'}
        events = [_record('tls', cert, 1, timestamp='2026-10-28T10:16:44.954880-0400'),   # 14:16 UTC
                  _record('tls', cert, 2, timestamp='2026-10-28T17:46:44.954880+0530'),   # 12:16 UTC
                  _record('tls', cert, 3, timestamp='2027-12-02T08:00:00.000000-0800'),   # 16:00 UTC
                  _record('tls', cert, 4, timestamp='2026-10-28T14:16:44.954880')]        # no zone: as it is
        found = [f['event']['src_port'] for f in findings.query_findings(self._db(events))['findings']]
        self.assertEqual(found, [40002, 40003])

    def test_which_names_a_certificate_covers(self):
        """Its SANs when it has any (its CN then doesn't count), or else
        its CN; a wildcard covers exactly one label; case doesn't matter."""
        cases = [  # (SNI, SANs, subject, mismatched?)
            ('www.example.com', ['www.example.com'], 'CN=other', False),
            ('WWW.Example.COM', ['www.example.com'], '', False),
            ('a.example.com', ['*.example.com'], 'CN=x', False),
            ('example.com', ['*.example.com'], 'CN=x', True),
            ('a.b.example.com', ['*.example.com'], 'CN=x', True),
            ('xexample.com', ['*.example.com'], 'CN=x', True),
            ('www.example.com', ['other.example'], 'CN=www.example.com', True),
            ('www.example.com', None, 'C=US, O=Example, CN=www.example.com', False),
            ('www.example.com', None, 'CN=www.example.com, O=Example', False),
            ('mail.example.com', None, 'CN=*.example.com', False),
            ('www.example.com', None, 'CN=www.example.org', True),
            ('www.example.com', None, 'O=No Common Name', True),
            ('10.1.2.3', ['device.local'], 'CN=device.local', False),
            ('2001:db8::1', None, 'CN=device.local', False),
            ('', None, 'CN=device.local', False),
            ('www.example.com', None, '', False),
        ]
        events = []
        for i, (sni, sans, subject, _) in enumerate(cases):
            body = {'sni': sni, 'subject': subject, 'issuerdn': 'CN=Some CA'}
            if sans is not None:
                body['subjectaltname'] = sans
            events.append(_record('tls', body, i, dest_port=i))
        found = {f['event']['dest_port'] for f in findings.query_findings(self._db(events))['findings']
                 if f['rule'] == 'tls_name_mismatch'}
        self.assertEqual([(c[0], c[1], c[2]) for i, c in enumerate(cases) if (i in found) != c[3]], [])

    def test_every_compromised_intermediate_is_found(self):
        """eMudhra's eight, as Mozilla bug 2083449 names them - whatever
        order the DN's parts come in"""
        names = [('EM DV TLS CA - G3B', 'eMudhra BV', 'NL'), ('EM OV TLS CA - G3B', 'eMudhra BV', 'NL'),
                 ('EM EV TLS CA - G3B', 'eMudhra BV', 'NL'), ('EM DV TLS CA - G3C', 'eMudhra Inc', 'US'),
                 ('EM OV TLS CA - G3C', 'eMudhra Inc', 'US'), ('EM EV TLS CA - G3C', 'eMudhra Inc', 'US'),
                 ('EM OV CS CA - G3B', 'eMudhra BV', 'NL'), ('EM OV CS CA - G3C', 'eMudhra Inc', 'US')]
        events = []
        for i, (cn, o, c) in enumerate(names):
            for dn in (f'C={c}, O={o}, CN={cn}', f'CN={cn}, O={o}, C={c}'):
                events.append(_record('tls', {'sni': f'h{i}.example', 'subject': f'CN=h{i}.example',
                                              'subjectaltname': [f'h{i}.example'], 'issuerdn': dn}, len(events)))
        result = findings.query_findings(self._db(events))
        self.assertEqual([(r['id'], r['count']) for r in result['rules']], [('tls_compromised_ca', 16)])
        details = sorted(f['detail'] for f in result['findings'])
        self.assertEqual(details[0], 'issued by EM DV TLS CA - G3B - CN=h0.example (for h0.example)')
        self.assertEqual(len(details), 16)

    def test_findings_carry_their_row_notes(self):
        path = self._db([_record('tunnel', {'type': 'GRE', 'returns_to_sender': True}, 1)])
        row_id = findings.query_findings(path)['findings'][0]['event']['id']
        db.set_row_note(path, 'events', row_id, 'checked - our scanner')
        self.assertEqual(findings.query_findings(path)['findings'][0]['event']['row_note'], 'checked - our scanner')

    def test_an_analysis_with_no_events(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        path = os.path.join(tmp, 'events.db')
        db.init_empty_db(path)
        self.assertEqual(findings.query_findings(path), {'rules': [], 'findings': []})

if __name__ == '__main__':
    unittest.main()
