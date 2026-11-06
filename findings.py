"""Findings: what the protocol records show is worth a look - a weakness, a
control action, a probe - gathered from every protocol into one list.

Each rule is one SQL condition over one event type's records in events.db,
so a rule reads only its own type's rows (by idx_event_type), and a short
detail line made from the matching record. A detail never carries a
password, even where the record keeps one.
"""

import json
import sqlite3

from db import (
    _build_search_terms,
    _build_where_conditions,
    _db_connection,
    _events_select,
    _has_acknowledged_alerts_table,
    _has_events_table,
    _has_fts5,
    get_row_notes,
)

SEVERITIES = ('high', 'medium', 'low')

# A rule's matches are grouped: the same detail on the same server (one
# certificate seen 200 times, one PLC written all day) is one finding,
# with how many records, from how many source hosts, and their first and
# last time. Groups shown per rule, and records listed for one group.
MAX_PER_RULE = 500
# Matches read per rule to group them - past this, a rule's groups (and
# each group's counts and times) are those of its first MAX_SCAN records;
# only the rule's own count of records is always exact
MAX_SCAN = 100_000


def _j(event_type, path):
    return f"json_extract(json_data, '$.{event_type}.{path}')"


def _has(event_type, path, values):
    """Any of a list field's items is one of values."""
    quoted = ', '.join("'" + v.replace("'", "''") + "'" for v in values)
    return (f"EXISTS (SELECT 1 FROM json_each(json_data, '$.{event_type}.{path}') "
            f"WHERE value IN ({quoted}))")


def _in(event_type, path, values):
    quoted = ', '.join("'" + v.replace("'", "''") + "'" for v in values)
    return f'{_j(event_type, path)} IN ({quoted})'


_NOTHING = (None, '', [], {})


def _join(*parts):
    """A detail line from its parts, leaving out the empty ones - and a
    (label, value) pair whole when its value is empty, so a missing value
    leaves no 'to', 'via' or '-' dangling."""
    out = []
    for part in parts:
        if isinstance(part, tuple):
            label, value = part
            if value not in _NOTHING:
                out.append(f'{label} {value}')
        elif part not in _NOTHING:
            out.append(str(part))
    return ' '.join(out)


def _counted(count, noun):
    """'1 route', '3 routes' - or '' with no count."""
    return '' if count in _NOTHING else f"{count} {noun}{'' if count == 1 else 's'}"


def _list(values, limit=3):
    values = list(values or ())
    more = f' (+{len(values) - limit} more)' if len(values) > limit else ''
    return ', '.join(str(v) for v in values[:limit]) + more


_TNS_ACCOUNT = ('CREATE USER', 'ALTER USER', 'DROP USER', 'GRANT', 'CREATE ROLE', 'ALTER ROLE', 'DROP ROLE')
_TNS_WRITES = ('INSERT', 'UPDATE', 'DELETE', 'MERGE', 'REVOKE', 'RENAME', 'COMMENT', 'AUDIT', 'NOAUDIT', 'FLASHBACK')


def _tns_statement(b):
    """A statement for a detail line: its first 120 characters (any
    IDENTIFIED BY password already masked in the record), and its result."""
    text = ' '.join(str(b.get('statement') or '').split())
    return _join(text if len(text) <= 120 else text[:120] + '...', ('-', b.get('result')))


_IEC104_CONTROL = ('Single command', 'Double command', 'Regulating step command', 'Set point (normalized)',
                   'Set point (scaled)', 'Set point (float)', 'Bitstring command', 'Reset process',
                   'Parameter activation')
# MongoDB commands that create or empower a user or role, and the
# handshake commands left out of a connection's detail line
_MONGO_ACCOUNT = ('createUser', 'updateUser', 'grantRolesToUser', 'createRole', 'updateRole', 'grantPrivilegesToRole')
_MONGO_QUIET = ('hello', 'ismaster', 'isMaster', 'buildinfo', 'buildInfo', 'ping', 'saslStart', 'saslContinue',
                'endSessions', 'getnonce')
# MMS services that run, stop or reload what a relay or controller executes
_MMS_PROGRAM = ('start', 'stop', 'resume', 'reset', 'kill', 'createProgramInvocation', 'deleteProgramInvocation',
                'initiateDownloadSequence', 'requestDomainDownload', 'loadDomainContent', 'deleteDomain')
# The alerts a TLS endpoint sends when it refuses the other's certificate
# (tshark's names)
_TLS_CERT_ALERTS = ('Bad Certificate', 'Unsupported Certificate', 'Certificate Revoked', 'Certificate Expired',
                    'Certificate Unknown', 'Unknown CA')
# A record's time in UTC, as Suricata writes a certificate's dates
# (2026-01-01T00:00:00): Suricata writes the record's own in the host's
# zone (2026-10-29T09:17:41.968994-0400) - UTC in the container, not on a
# server run outside it. SQLite takes the offset as -04:00; a time without
# one is used as it is.
_UTC_TIME = ("coalesce(strftime('%Y-%m-%dT%H:%M:%S', substr(timestamp, 1, 19) "
             "|| substr(timestamp, -5, 3) || ':' || substr(timestamp, -2)), substr(timestamp, 1, 19))")
# A certificate outside its validity at the time of the connection - not
# today, or every old capture's would be expired
_TLS_OUT_OF_DATE = (f"({_j('tls', 'notafter')} < {_UTC_TIME} "
                    f"OR {_j('tls', 'notbefore')} > {_UTC_TIME})")


def _name_matches(name, pattern):
    """SQL: whether a host name matches a certificate's name - the same,
    ignoring case, or under its wildcard, which stands for exactly one
    label (*.example.com covers www.example.com, not example.com or
    a.b.example.com). Both are lowercased SQL expressions."""
    suffix = f'substr({pattern}, 2)'
    return (f"({name} = {pattern} OR (substr({pattern}, 1, 2) = '*.' AND length({name}) > length({suffix}) "
            f"AND substr({name}, length({name}) - length({suffix}) + 1) = {suffix} "
            f"AND instr(substr({name}, 1, length({name}) - length({suffix})), '.') = 0))")


_SNI = f"lower({_j('tls', 'sni')})"
def _cn(field):
    """A TLS record's distinguished name field's CN, lowercased (Suricata
    writes a DN's parts separated by ', ')."""
    rest = f"substr({_j('tls', field)}, instr({_j('tls', field)}, 'CN=') + 3)"
    return (f"lower(CASE WHEN instr({rest}, ', ') > 0 "
            f"THEN substr({rest}, 1, instr({rest}, ', ') - 1) ELSE {rest} END)")


_SUBJECT_CN = _cn('subject')
_HAS_SANS = "json_array_length(json_data, '$.tls.subjectaltname') > 0"
# A certificate that doesn't name the host the client asked for: its SANs,
# when it has any - or else its subject's CN (RFC 6125) - cover no match
# for the SNI. Not an SNI that's an address (some clients send one, which
# only an IP SAN could match), nor a record with no certificate (TLS 1.3
# encrypts it).
_TLS_NAME_MISMATCH = (
    f"coalesce({_j('tls', 'sni')}, '') != '' AND coalesce({_j('tls', 'subject')}, '') != '' "
    f"AND instr({_j('tls', 'sni')}, ':') = 0 AND {_j('tls', 'sni')} GLOB '*[^0-9.]*' "
    f"AND CASE WHEN {_HAS_SANS} "
    f"THEN NOT EXISTS (SELECT 1 FROM json_each(json_data, '$.tls.subjectaltname') "
    f"WHERE {_name_matches(_SNI, 'lower(value)')}) "
    f"ELSE instr({_j('tls', 'subject')}, 'CN=') = 0 OR NOT {_name_matches(_SNI, _SUBJECT_CN)} END")


def _tls_certificate(b):
    """The certificate a TLS record names, and for which host."""
    return _join(b.get('subject'), f"(for {b['sni']})" if b.get('sni') else '')


# Intermediate CAs whose private keys are known to be recoverable, so a
# certificate they issued could be anyone's forgery - by CN, with the
# operator's name in the DN too. eMudhra's eight (Oct 2026, Mozilla bug
# 2083449): weak P-384 keys from an April 2025 ceremony; revoked Oct 18
# 2026, and they never issued a real certificate, so every one on the wire
# is forged. Sectigo's cross-signs of them carry the same names and keys.
_COMPROMISED_CAS = (
    ('eMudhra', ('EM DV TLS CA - G3B', 'EM OV TLS CA - G3B', 'EM EV TLS CA - G3B',
                 'EM DV TLS CA - G3C', 'EM OV TLS CA - G3C', 'EM EV TLS CA - G3C',
                 'EM OV CS CA - G3B', 'EM OV CS CA - G3C')),
)
_ISSUED_BY_COMPROMISED_CA = '(' + ' OR '.join(
    f"(instr({_j('tls', 'issuerdn')}, '{operator}') > 0 AND {_cn('issuerdn')} IN "
    f"({', '.join(repr(name.lower()) for name in names)}))"
    for operator, names in _COMPROMISED_CAS) + ')'


def _issuer_cn(b):
    issuer = b.get('issuerdn') or ''
    return issuer.split('CN=', 1)[1].split(', ', 1)[0] if 'CN=' in issuer else issuer


_DEFAULT_ROUTE = ("EXISTS (SELECT 1 FROM json_each(json_data, '$.rip.routes') "
                  "WHERE value LIKE '0.0.0.0/0 %' OR value LIKE '::/0 %')")


class Rule:
    __slots__ = ('id', 'severity', 'event_type', 'title', 'condition', 'detail', 'why')

    def __init__(self, id, severity, event_type, title, condition, detail, why):
        self.id, self.severity, self.event_type, self.title = id, severity, event_type, title
        self.condition, self.detail, self.why = condition, detail, why


# Most severe first; within a severity, roughly by how rarely the thing
# found is innocent
RULES = (
    Rule('tls_compromised_ca', 'high', 'tls', 'TLS certificate from a compromised CA',
         _ISSUED_BY_COMPROMISED_CA,
         lambda b: _join(('issued by', _issuer_cn(b)), ('-', _tls_certificate(b))),
         "A certificate signed by an intermediate CA whose private key could be recovered - eMudhra's "
         "eight, revoked in October 2026, never issued a real one, so this is a forgery made with the "
         "recovered key: someone in the middle of this connection, or a server impersonating another. "
         "Browsers that enforce Certificate Transparency refuse it; apps, scripts, devices and older "
         "trust stores may not, so check whether the client went on talking. Seen only where the "
         "certificate went out readable - TLS 1.2 and earlier."),
    Rule('ipmi_cipher_zero', 'high', 'ipmi', 'IPMI accepts cipher zero',
         _has('ipmi', 'weaknesses', ['cipher zero accepted']),
         lambda b: _join(('privilege', b.get('requested_privilege'))),
         "An IPMI 2.0 controller that accepts cipher suite 0 logs anyone in with any password "
         "(CVE-2013-4782)."),
    Rule('ipmi_anonymous', 'high', 'ipmi', 'IPMI allows anonymous logins',
         _has('ipmi', 'weaknesses', ['anonymous login', 'null user names']),
         lambda b: _list(w for w in b.get('weaknesses', ()) if w in ('anonymous login', 'null user names')),
         'A management controller that takes a login with no user name, or a null user, gives '
         'full control of the server to anyone who can reach it.'),
    Rule('ipmi_weak_auth', 'high', 'ipmi', 'IPMI offers weak authentication',
         _has('ipmi', 'weaknesses', ['no authentication offered', 'cleartext password']),
         lambda b: _list(w for w in b.get('weaknesses', ()) if w in ('no authentication offered',
                                                                    'cleartext password')),
         'An IPMI 1.5 login with no authentication, or with the password sent as it is.'),
    Rule('opcua_cleartext_password', 'high', 'opcua', 'OPC UA password sent unencrypted',
         f"{_j('opcua', 'password')} IS NOT NULL",
         lambda b: _join(('user', b.get('username')), ('on', b.get('endpoint'))),
         'The login password crossed the network readable - anyone on the path has it.'),
    Rule('telnet_login', 'high', 'telnet', 'Telnet login in the clear',
         f"(coalesce({_j('telnet', 'username')}, '') != '' OR coalesce({_j('telnet', 'password')}, '') != '')",
         lambda b: _join(f"user {b['username']}" if b.get('username') else 'a password, no user name',
                         '- login failed' if b.get('login') == 'failed' else ''),
         "Telnet sends the user name and password as typed; the device's banner is on the record."),
    Rule('rsh_login', 'high', 'rsh', 'rsh, rlogin or rexec login in the clear',
         f"{_j('rsh', 'user')} IS NOT NULL",
         lambda b: _join(b.get('service'), ('as', b.get('user')), ('from', b.get('local_user')),
                         ('-', b.get('command')), ('-', b.get('result'))),
         "The BSD remote shells send everything as typed - rexec its password, rlogin the one typed at its "
         "prompt - and rsh and rlogin trust the client's word for who it is. The command run is on the record."),
    Rule('s7_plc_control', 'high', 's7comm', 'S7 PLC started or stopped',
         _in('s7comm', 'function', ['PLC Stop', 'PLC Control']),
         lambda b: _join(b.get('function'), (b.get('response') or {}).get('error')),
         "A Siemens PLC's run state changed over the network - the step before reprogramming it, "
         "or stopping the process it runs."),
    Rule('s7_download', 'high', 's7comm', 'S7 program download',
         _in('s7comm', 'function', ['Request download', 'Download block', 'Download ended']),
         lambda b: b.get('function', ''),
         "Program blocks written to a Siemens PLC - how its logic is changed."),
    Rule('bacnet_device_control', 'high', 'bacnet', 'BACnet device restarted or silenced',
         _in('bacnet', 'service', ['reinitializeDevice', 'deviceCommunicationControl']),
         lambda b: _join(b.get('service'), b.get('state'), b.get('result')),
         'A building controller told to restart, or to stop talking, over the network.'),
    Rule('goose_anomaly', 'high', 'goose', 'GOOSE state number jumped or reset',
         f"{_j('goose', 'anomaly')} IS NOT NULL",
         lambda b: b.get('anomaly', ''),
         "A protection relay's state number should only go up by one - a jump or reset is what a "
         "forged or replayed message looks like."),
    Rule('mms_control', 'high', 'mms_action', 'MMS control command or program change',
         f"({_j('mms_action', 'control')} IS NOT NULL OR {_in('mms_action', 'service', list(_MMS_PROGRAM))})",
         lambda b: _join(b.get('control') or b.get('service'), b.get('object'), ('-', b.get('result'))),
         'An IEC 61850 operate, select or cancel - switching a breaker or other controllable equipment - '
         'or a program started, stopped or killed, or a domain downloaded, on a relay or controller.'),
    Rule('mongodb_destroy', 'high', 'mongodb_action', 'MongoDB database or collection dropped',
         _in('mongodb_action', 'command', ['drop', 'dropDatabase', 'dropAllUsersFromDatabase', 'shutdown']),
         lambda b: _join(b.get('command'), '.'.join(filter(None, (b.get('database'), b.get('collection')))), ('-', b.get('result'))),
         'Data or users deleted wholesale, or the server shut down - what a ransom attack on an open '
         'MongoDB server does before it leaves its note.'),
    Rule('mongodb_user_change', 'high', 'mongodb_action', 'MongoDB user or role created or granted',
         _in('mongodb_action', 'command', list(_MONGO_ACCOUNT)),
         lambda b: _join(b.get('command'), b.get('user') or b.get('role'), _list(b.get('roles', ())),
                         ('-', b.get('result'))),
         'A user or role created, changed or given more rights - a way back in that outlasts the session.'),
    Rule('memcache_amplifier', 'high', 'memcache', 'memcached answering over UDP',
         f"{_j('memcache', 'amplification')} IS NOT NULL",
         lambda b: f"{b['amplification']:g}x amplification - {b.get('response_bytes') or 0:,} bytes back for "
                   f"{b.get('request_bytes') or 0:,}",
         "A memcached server answered over UDP - the amplifier of the 2018 attacks (CVE-2018-1000115): a "
         "request's source address forged, its reply goes to the victim, up to thousands of times larger. "
         'Turn UDP off (-U 0) or keep the port off the internet.'),
    Rule('memcache_flush', 'high', 'memcache', 'memcached flushed or shut down',
         f"({_j('memcache', 'commands.flush_all')} IS NOT NULL OR {_j('memcache', 'commands.shutdown')} IS NOT NULL)",
         lambda b: _join(_list([c for c in ('flush_all', 'shutdown') if c in (b.get('commands') or {})]),
                         ('-', 'answered' if b.get('answered') else 'no answer')),
         'Every item in the cache dropped, or the server stopped - what an application does rarely, and '
         'anyone who reaches an open memcached can do.'),
    Rule('tns_account_change', 'high', 'tns_statement', 'Oracle user or privilege created or granted',
         _in('tns_statement', 'verb', list(_TNS_ACCOUNT)),
         _tns_statement,
         'A database user or role created, changed, unlocked or given more rights - a way back in that '
         'outlasts the session.'),
    Rule('tns_destroy', 'high', 'tns_statement', 'Oracle table or object dropped',
         f"({_j('tns_statement', 'verb')} LIKE 'DROP %' OR {_j('tns_statement', 'verb')} LIKE 'TRUNCATE%' "
         f"OR {_j('tns_statement', 'verb')} = 'PURGE') AND NOT {_in('tns_statement', 'verb', list(_TNS_ACCOUNT))}",
         _tns_statement,
         'Data or a database object deleted wholesale - a table, view, procedure, tablespace... dropped '
         'or truncated.'),
    Rule('pn_dcp_set', 'high', 'pn_dcp', 'PROFINET device renamed, readdressed or reset',
         f"{_j('pn_dcp', 'service')} = 'Set' AND "
         + _has('pn_dcp', 'changes', ['station name', 'IP address', 'DHCP', 'reset factory settings', 'reset to factory']),
         lambda b: _join(_list(b.get('changes', ())), ('to', b.get('station_name') or b.get('ip')), ('-', b.get('result'))),
         "PROFINET DCP has no authentication: anyone on the segment can change a device's name or address, "
         "or reset it, cutting it off from its controller."),
    Rule('slp_registration', 'high', 'slp', 'SLP accepts registrations',
         f"{_j('slp', 'function')} = 'Service Registration' AND {_j('slp', 'status')} = 'OK'",
         lambda b: _join(b.get('url'), f"({b['length']} bytes)" if b.get('length') else ''),
         'A host that registers services from anyone can be made to send large replies to a '
         'forged address (CVE-2023-29552).'),

    Rule('tls_certificate_refused', 'medium', 'tls_failure', 'TLS certificate refused',
         _has('tls_failure', 'alerts', [f'{side}: {a}' for side in ('client', 'server') for a in _TLS_CERT_ALERTS]),
         lambda b: _join(next((a for a in b.get('alerts', ()) if a.split(': ', 1)[-1] in _TLS_CERT_ALERTS), ''),
                         ('-', b.get('subject')), f"(for {b['sni']})" if b.get('sni') else ''),
         "One end refused the other's certificate - untrusted (Unknown CA), expired, revoked or otherwise bad. "
         "Self-signed devices, TLS-inspecting proxies and someone in the middle all look like this. Seen "
         "where the alert went out readable: always in TLS 1.2 and earlier, and in TLS 1.3 from some clients "
         "(OpenSSL's) - whose certificate, encrypted, goes unnamed."),
    Rule('s7_write', 'medium', 's7comm', 'S7 PLC memory written',
         _in('s7comm', 'function', ['Write Var']),
         lambda b: _list(i.get('area') for i in b.get('items', ()) if i.get('area'))
         or _counted(b.get('item_count') or (b.get('response') or {}).get('item_count'), 'item'),
         "Values written straight into a Siemens PLC's memory."),
    Rule('iec104_control', 'medium', 'iec104', 'IEC 104 control command',
         _in('iec104', 'action', list(_IEC104_CONTROL)),
         lambda b: _join(b.get('action'), ('to IOA', b.get('ioa')), ('-', b.get('result'))),
         'A command or set point sent to a substation - switching or adjusting equipment.'),
    Rule('opcua_change', 'medium', 'opcua_action', 'OPC UA write or method call',
         '1',
         lambda b: _join(b.get('service'), b.get('node'), ('-', b.get('result'))),
         'A client changed a node, called a method, or added or deleted nodes.'),
    Rule('mms_change', 'medium', 'mms_action', 'MMS write or definition change',
         f"({_j('mms_action', 'control')} IS NULL AND NOT {_in('mms_action', 'service', list(_MMS_PROGRAM))})",
         lambda b: _join(b.get('service'), b.get('object'), ('-', b.get('result'))),
         'A client wrote a variable, or defined or deleted variables, lists, events or journals, on an MMS server.'),
    Rule('mongodb_unauthenticated', 'medium', 'mongodb', 'MongoDB answered without a login',
         f"{_j('mongodb', 'unauthenticated')} = 1",
         lambda b: _join(_list(c for c in b.get('commands', {}) if c not in _MONGO_QUIET), ('by', b.get('driver'))),
         "The server answered more than a handshake on a connection that never logged in - it's open to "
         "anyone who reaches it. (A connection that logged in before the capture started looks the same.)"),
    Rule('mongodb_change', 'medium', 'mongodb_action', 'MongoDB write or change',
         f"NOT {_in('mongodb_action', 'command', ['drop', 'dropDatabase', 'dropAllUsersFromDatabase', 'shutdown'] + list(_MONGO_ACCOUNT))}",
         lambda b: _join(b.get('command'), '.'.join(filter(None, (b.get('database'), b.get('collection')))), ('-', b.get('result'))),
         'Documents inserted, updated or deleted, or a collection, index or setting changed.'),
    Rule('openvpn_tunnel', 'medium', 'openvpn', 'OpenVPN tunnel',
         f"{_j('openvpn', 'stage')} = 'established'",
         lambda b: _join(('to', (b.get('certificate') or {}).get('subject') or b.get('sni')),
                         ('-', _counted((b.get('data_to_server') or 0) + (b.get('data_to_client') or 0), 'data packet'))),
         "A VPN tunnel carried data. From inside a network it's a way around its monitoring and controls - "
         "check it's one you run."),
    Rule('wireguard_tunnel', 'medium', 'wireguard', 'WireGuard tunnel',
         f"{_j('wireguard', 'stage')} = 'established'",
         lambda b: _counted((b.get('data_to_server') or 0) + (b.get('data_to_client') or 0), 'data packet'),
         "A VPN tunnel carried data. From inside a network it's a way around its monitoring and controls - "
         "check it's one you run."),
    Rule('tns_change', 'medium', 'tns_statement', 'Oracle write or change',
         f"({_in('tns_statement', 'verb', list(_TNS_WRITES))} OR {_j('tns_statement', 'verb')} LIKE 'CREATE %' "
         f"OR ({_j('tns_statement', 'verb')} LIKE 'ALTER %' AND {_j('tns_statement', 'verb')} != 'ALTER SESSION')) "
         f"AND NOT {_in('tns_statement', 'verb', list(_TNS_ACCOUNT))}",
         _tns_statement,
         'Rows inserted, updated or deleted, or a table, procedure or other object created or changed. '
         "An application's writes look the same - check who sent them."),
    Rule('tns_listener_command', 'medium', 'tns', 'Oracle listener command',
         f"{_j('tns', 'command')} IS NOT NULL AND lower({_j('tns', 'command')}) != 'ping'",
         lambda b: _join(b.get('command'), ('-', b.get('error') or b.get('result'))),
         "A command to the TNS listener itself - lsnrctl's status, version or services, which describe the "
         'server, or stop, set or reload, which change it. From anywhere but the server or an admin '
         "host, it's a survey or an attack."),
    Rule('socks_open', 'medium', 'socks', 'SOCKS proxy without authentication',
         f"{_j('socks', 'auth_method')} = 'no authentication' AND {_j('socks', 'status')} = 'succeeded'",
         lambda b: _join(('to', _join(b.get('request_name') or b.get('request_host'), b.get('request_port')))),
         'An open proxy relays anyone - often how traffic is laundered through a host.'),
    Rule('xdmcp_offered', 'medium', 'xdmcp', 'XDMCP login screen offered',
         _in('xdmcp', 'result', ['willing', 'accepted', 'managed']),
         lambda b: _join(b.get('server_host_name'), ('-', b.get('result'))),
         "An X login manager answering the network hands out a graphical login, unencrypted."),
    Rule('rip_default_route', 'medium', 'rip', 'RIP default route announced',
         _DEFAULT_ROUTE,
         lambda b: _list(r for r in b.get('routes', ()) if r.startswith(('0.0.0.0/0 ', '::/0 '))),
         'Whoever announces the default route gets the traffic for everywhere else - expected '
         'from a router, not from any other host.'),
    Rule('rip_cleartext_password', 'medium', 'rip', 'RIPv2 password in the clear',
         f"{_j('rip', 'authentication')} = 'simple password'",
         lambda b: _counted(b.get('route_count'), 'route'),
         'Simple-password authentication sends the password readable with every update.'),
    Rule('tunnel_return', 'medium', 'tunnel', 'Tunnel packet addressed back to its sender',
         f"{_j('tunnel', 'returns_to_sender')} = 1",
         lambda b: b.get('type', ''),
         "A scanner's test of whether a host unwraps tunnels from anyone - and would forward "
         "spoofed traffic."),
    Rule('rpc_exports', 'medium', 'rpc', 'NFS exports listed',
         f"{_j('rpc', 'exports')} IS NOT NULL",
         lambda b: _list(b.get('exports')),
         "A host listing its NFS shares to whoever asked."),
    Rule('syslog_critical', 'medium', 'syslog', 'Critical syslog message',
         _in('syslog', 'severity', ['emerg', 'alert', 'crit']),
         lambda b: _join(b.get('hostname'), b.get('program'), ('-', (b.get('message') or '')[:120])),
         'A device logging an emergency, alert or critical condition.'),

    Rule('tls_self_signed', 'medium', 'tls', 'TLS self-signed certificate',
         f"{_j('tls', 'issuerdn')} = {_j('tls', 'subject')} AND {_j('tls', 'subject')} != ''",
         _tls_certificate,
         "A certificate that vouches for itself: what malware command-and-control servers and interception "
         "tools generate, and common on appliances and lab servers. No client trusts one unless told to."),

    Rule('tls_certificate_out_of_date', 'low', 'tls', 'TLS certificate expired or not yet valid',
         _TLS_OUT_OF_DATE,
         lambda b: _join('valid', (b.get('notbefore') or '?')[:10], 'to', (b.get('notafter') or '?')[:10],
                         ('-', _tls_certificate(b))),
         'The server offered a certificate outside its validity dates at the time - a forgotten renewal, a '
         'device with its clock wrong, or a certificate made up on the spot.'),
    Rule('tls_name_mismatch', 'low', 'tls', "TLS certificate doesn't name the host",
         _TLS_NAME_MISMATCH,
         lambda b: _join(('asked for', b.get('sni')),
                         ('- certificate for', _list(b.get('subjectaltname')) or b.get('subject'))),
         "The client asked for one host and got a certificate for others - a server's default certificate, "
         "a shared host or CDN that doesn't serve that name, or someone in the middle answering for it."),
    Rule('pn_dcp_identify_all', 'low', 'pn_dcp', 'PROFINET devices discovered',
         f"{_j('pn_dcp', 'service')} = 'Identify' AND {_j('pn_dcp', 'query')} = 'all'",
         lambda b: f"{_counted(b['responses'], 'device')} answered" if b.get('responses') else 'no answer',
         "A DCP Identify All lists every PROFINET device on the segment, with its name, type and address - "
         "routine from an engineering station, a survey from anywhere else."),
    Rule('openvpn_retries', 'low', 'openvpn', 'OpenVPN client retrying unanswered',
         f"{_j('openvpn', 'stage')} = 'client reset only' AND {_j('openvpn', 'client_resets')} >= 2",
         lambda b: _counted(b.get('client_resets'), 'attempt'),
         "A client kept trying to open an OpenVPN session that nothing answered - a VPN configured to "
         "reach out, and blocked or gone. (A scanner's probe is one attempt, and isn't listed.)"),
    Rule('wireguard_retries', 'low', 'wireguard', 'WireGuard peer retrying unanswered',
         f"{_j('wireguard', 'stage')} = 'initiation only' AND {_j('wireguard', 'initiations')} >= 2",
         lambda b: _counted(b.get('initiations'), 'attempt'),
         "A peer kept trying to open a WireGuard tunnel that nothing answered - a VPN configured to reach "
         "out, and blocked or gone, or a peer whose key the other end doesn't accept. (A scanner's probe is "
         "one attempt, and isn't listed.)"),
    Rule('memcache_stats', 'low', 'memcache', 'memcached stats answered',
         f"{_j('memcache', 'commands.stats')} IS NOT NULL AND {_j('memcache', 'answered')} = 1",
         lambda b: _join(_list(b.get('stats', ())), ('- version', b.get('version'))),
         'A memcached server told a client its stats - version, uptime, connections, item counts, and with '
         "stats items or cachedump, what's stored. Routine from monitoring, a survey from anywhere else."),
    Rule('tns_login_failed', 'low', 'tns', 'Oracle login failed',
         f"{_j('tns', 'login')} = 'failed'",
         lambda b: _join(b.get('db_user'), ('-', b.get('login_error'))),
         'A database login refused - a mistyped password, or one guess of many.'),
    Rule('tns_unknown_service', 'low', 'tns', 'Oracle service or SID unknown',
         f"{_j('tns', 'result')} = 'refused' AND {_in('tns', 'error', ['ORA-12505', 'ORA-12514'])}",
         lambda b: _join(('SID', b.get('sid')), ('service', b.get('service_name'))),
         "The listener didn't know the SID or service a client asked for - a misconfigured client, or "
         "one guessing SIDs (many unknown ones from one host)."),
    Rule('rsh_answering', 'low', 'rsh', 'rsh, rlogin or rexec service answering',
         f"{_j('rsh', 'probe')} IS NOT NULL AND {_j('rsh', 'result')} != 'no response'",
         lambda b: _join(b.get('service'), ('-', b.get('error') or b.get('result'))),
         "Something that wasn't a login reached a remote shell service and it answered - a scanner found it "
         "listening."),
    Rule('rip_whole_table', 'low', 'rip', 'RIP routing table handed out',
         f"{_j('rip', 'whole_table')} = 1 AND {_j('rip', 'responses')} IS NOT NULL",
         lambda b: _counted(b.get('route_count'), 'route'),
         'A router answered a request for its whole table - a map of the network for the asking.'),
    Rule('rpc_portmapper', 'low', 'rpc', 'RPC services listed',
         f"{_j('rpc', 'mappings')} IS NOT NULL",
         lambda b: _counted(len(b.get('mappings') or ()), 'service'),
         "A portmapper listing every RPC service the host runs."),
    Rule('bacnet_write', 'low', 'bacnet', 'BACnet property or file written',
         _in('bacnet', 'service', ['writeProperty', 'writePropertyMultiple', 'atomicWriteFile']),
         lambda b: _join(b.get('service'), b.get('object'), b.get('property'), ('-', b.get('result'))),
         "Routine in building automation, but how a controller's setpoints and schedules are "
         "changed."),
    Rule('slp_answered', 'low', 'slp', 'SLP service answers',
         f"{_j('slp', 'response')} IS NOT NULL AND {_j('slp', 'function')} != 'Service Registration'",
         lambda b: _join(b.get('function'), ('-', b.get('status'))),
         'Exposed to the internet, SLP is how scanners find ESXi hosts and amplifiers.'),
    Rule('coap_discovery', 'low', 'coap', 'CoAP resources listed',
         f"{_j('coap', 'resources')} IS NOT NULL",
         lambda b: _list(b.get('resources')),
         "A device answering /.well-known/core with what it serves."),
    Rule('l2tp_no_auth', 'low', 'l2tp', 'L2TP tunnel without tunnel authentication',
         f"{_j('l2tp', 'state')} = 'established' AND {_j('l2tp', 'tunnel_authentication')} IS NULL",
         lambda b: _join(b.get('client_host_name'), ('to', b.get('server_host_name'))),
         "Common, with IPsec protecting it - seen at all, this control connection is outside IPsec."),
    Rule('radius_reject', 'low', 'radius', 'RADIUS login rejected',
         f"{_j('radius', 'result')} = 'rejected'",
         lambda b: _join(('user', b.get('user')), ('via', b.get('nas_ip'))),
         'Many of them, for many users, is password guessing.'),
)

RULES_BY_ID = {r.id: r for r in RULES}


def _rule_sql(conn, rule, terms, has_fts, columns, group=None):
    """The SELECT of columns (of events) for rule's matches - of one
    group's addresses, given one - and its parameters. A search joins the
    FTS index, whose own json_data column means every reference to events'
    must be qualified then."""
    alias = 'e.' if terms and has_fts else ''
    qualify = (lambda sql: sql.replace('json_data', 'e.json_data')) if alias else (lambda sql: sql)
    cols = ', '.join(alias + c if c != 'COUNT(*)' else c for c in columns)
    select, type_col = _events_select(terms, has_fts, cols, cols)
    conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts,
                                                 rule.event_type, type_col)
    conditions.append(f'({qualify(rule.condition)})')
    if group is not None:
        for column, missing in (('dest_ip', "''"), ('dest_port', '0')):
            # (a record without one is stored with '' or 0, or NULL)
            if group.get(column) in (None, ''):
                conditions.append(f'coalesce({alias}{column}, {missing}) = {missing}')
            else:
                conditions.append(f'{alias}{column} = ?')
                params.append(group[column])
    return f"{select} WHERE {' AND '.join(conditions)}", params, alias


def _detail(rule, event):
    try:
        return str(rule.detail(event.get(rule.event_type) or {}))
    except (AttributeError, TypeError, KeyError):
        return ''


def _group_key(event, detail):
    # (no port and port 0 alike, as events.db stores them - and as a
    # group's own records are looked up)
    return detail, event.get('dest_ip') or '', event.get('dest_port') or 0


def _matches(conn, rule, terms, has_fts, group=None, limit=MAX_SCAN):
    """A rule's matching records, oldest first, each with its detail line."""
    sql, params, alias = _rule_sql(conn, rule, terms, has_fts, ['id', 'json_data'], group)
    for row_id, data in conn.execute(f'{sql} ORDER BY {alias}timestamp LIMIT {limit}', params):
        try:
            event = json.loads(data)
        except ValueError:
            continue
        event['id'] = row_id
        yield event, _detail(rule, event)


def query_findings(db_path, q=None, counts_only=False, group=None):
    """Every rule's matches in events.db, grouped (MAX_PER_RULE):
    {'rules': [{id, title, severity, event_type, why, count, groups}],
    'findings': [{rule, severity, title, detail, event, count, sources,
    first, last}]} (counts_only: no findings, but each rule's groups) - event being a group's first record, sources how many
    source hosts its records came from - in RULES' order (most severe
    first), then by time. A search (q) narrows both, as it does every tab.
    Given a group - {rule, detail, dest_ip, dest_port}, as a finding names
    it - its own records instead, one finding each, at most MAX_PER_RULE
    of them."""
    result = {'rules': [], 'findings': []}
    rules = RULES
    if group is not None:
        rule = RULES_BY_ID.get(group.get('rule'))
        if rule is None:
            return result
        rules = (rule,)
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return result
        types = {row[0] for row in conn.execute('SELECT DISTINCT event_type FROM events')}
        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False
        for rule in rules:
            if rule.event_type not in types:
                continue
            try:
                sql, params, _ = _rule_sql(conn, rule, terms, has_fts, ['COUNT(*)'], group)
                count = conn.execute(sql, params).fetchone()[0]
            except sqlite3.OperationalError:
                continue
            if not count:
                continue
            entry = {'id': rule.id, 'title': rule.title, 'severity': rule.severity,
                     'event_type': rule.event_type, 'why': rule.why, 'count': count}
            result['rules'].append(entry)
            base = {'rule': rule.id, 'severity': rule.severity, 'title': rule.title}
            if group is not None:
                members = [(e, d) for e, d in _matches(conn, rule, terms, has_fts, group) if d == group.get('detail', '')]
                entry['count'] = len(members)
                for event, detail in members[:MAX_PER_RULE] if not counts_only else ():
                    when = event.get('timestamp') or ''
                    result['findings'].append({**base, 'detail': detail, 'event': event, 'count': 1, 'sources': 1,
                                               'first': when, 'last': when})
                continue
            groups, sources = {}, {}
            for event, detail in _matches(conn, rule, terms, has_fts):
                key = _group_key(event, detail)
                when = event.get('timestamp') or ''
                found = groups.get(key)
                if found is None:
                    groups[key] = {**base, 'detail': detail, 'event': event, 'count': 1, 'first': when, 'last': when}
                    sources[key] = {event.get('src_ip')}
                else:
                    found['count'] += 1
                    found['last'] = max(found['last'], when)
                    sources[key].add(event.get('src_ip'))
            for key, found in groups.items():
                found['sources'] = len(sources[key])
            entry['groups'] = len(groups)
            if not counts_only:
                result['findings'].extend(list(groups.values())[:MAX_PER_RULE])
    if result['findings']:
        ids = sorted({f['event']['id'] for f in result['findings']})
        notes = {}
        for i in range(0, len(ids), 500):
            notes.update(get_row_notes(db_path, 'events', ids[i:i + 500]))
        for f in result['findings']:
            if f['event']['id'] in notes:
                f['event']['row_note'] = notes[f['event']['id']]
    order = {r.id: i for i, r in enumerate(RULES)}
    result['findings'].sort(key=lambda f: (order[f['rule']], f['event'].get('timestamp') or ''))
    return result
