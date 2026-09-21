# Event Types

| Type | Description | Key fields |
|---|---|---|
| `alert` | Suricata rule matches | `alert.signature`, `alert.severity`, `alert.category`, `alert.rule` |
| `dns` | DNS queries/responses | `dns.rrname`, `dns.rrtype`, `dns.rcode` |
| `http` | HTTP requests (also covers HTTP/2, including cleartext h2c - Suricata logs both under `event_type: "http"` with the same field names, adding `http.version`/`http.http2`/`http.request_headers` for HTTP/2 frames) | `http.http_method`, `http.url`, `http.http_content_type`, `http.status` |
| `tls` | TLS handshakes | `tls.sni`, `tls.version`, `tls.subject`, `tls.issuerdn` |
| `flow` | Network flow summaries | `flow.pkts_toserver`, `flow.pkts_toclient`, `flow.bytes_toserver`, `flow.bytes_toclient`, `flow.state` |
| `ftp` | FTP commands | `ftp.command`, `ftp.command_data`, `ftp.completion_code`, `ftp.reply` |
| `anomaly` | Protocol anomalies | `anomaly.event`, `anomaly.type`, `anomaly.layer`, `anomaly.app_proto` |
| `fileinfo` | File transfers | `fileinfo.filename`, `fileinfo.magic` |
| `filealerts` | YARA matches on extracted files | `filealerts.rule_name`, `filealerts.sha256`, `filealerts.tags` |
| `dnp3` | DNP3 industrial-control events | `dnp3.src`, `dnp3.dst`, `dnp3.type` |
| `modbus` | Modbus industrial-control events | `modbus.request.function_code`, `modbus.request.unit_id` |
| `pgsql` | PostgreSQL protocol events | `pgsql.request.simple_query`, `pgsql.response.command_completed` |
| `enip` | EtherNet/IP (CIP) industrial-control events | `enip.request.command`, `enip.response.status` |
| `ntp` | NTP requests/responses | `ntp.version`, `ntp.mode`, `ntp.stratum`, `ntp.reference_id` |
| `websocket` | WebSocket frames | `websocket.opcode`, `websocket.fin`, `websocket.payload_printable`/`payload_base64` |
| `pop3` | POP3 mail retrieval | `pop3.request.command`/`args`, `pop3.response.status`/`data` |
| `mdns` | Multicast DNS (.local) | `mdns.queries[].rrname`/`rrtype` (same V3-style array shape as `dns` - see note below) |
| `ldap` | LDAP directory operations | keyed by operation type (`bind_request`/`search_request`/`modify_request`/...), e.g. `ldap.request.operation`, `ldap.responses[].bind_response.result_code` |
| `quic` | QUIC connections | `quic.sni`, `quic.version`, `quic.ja3.hash`, `quic.ja3s.hash` |
| `dhcp` | DHCP lease negotiation | `dhcp.dhcp_type`, `dhcp.client_mac`, `dhcp.assigned_ip`, `dhcp.hostname` |
| `ftp_data` | FTP data-channel transfers | `ftp_data.command`, `ftp_data.filename` |
| `smb` | SMB/CIFS file-share operations | `smb.command`, `smb.filename`, `smb.share`, `smb.ntlmssp.user` |
| `ssh` | SSH handshakes | `ssh.client.software_version`, `ssh.server.software_version` |
| `krb5` | Kerberos authentication | `krb5.cname`, `krb5.sname`, `krb5.realm`, `krb5.error_code` |
| `sip` | SIP (VoIP signaling) | `sip.method`, `sip.uri`, `sip.code`, `sip.reason` |
| `snmp` | SNMP requests | `snmp.version`, `snmp.pdu_type`, `snmp.community` |
| `mqtt` | MQTT messages | keyed by message subtype (`connect`, `publish`, `subscribe`, ...), e.g. `mqtt.publish.topic` |
| `dcerpc` | DCE/RPC calls | `dcerpc.interfaces[].uuid`, `dcerpc.request.opnum`, `dcerpc.call_id` |
| `rdp` | RDP connection negotiation | `rdp.event_type`, `rdp.cookie`, `rdp.client_name` |
| `tftp` | TFTP transfers | `tftp.packet`, `tftp.file`, `tftp.mode` |
| `ike` | IKE/IPsec key exchange | `ike.exchange_type`, `ike.version_major`/`version_minor`, `ike.init_spi` |
| `nfs` | NFS operations | `nfs.procedure`, `nfs.filename` |
| `rfb` | RFB/VNC connections | `rfb.client_protocol_version.{major,minor}`, `rfb.server_protocol_version.{major,minor}`, `rfb.authentication.security_type` |
| `bittorrent_dht` | BitTorrent DHT messages | `bittorrent_dht.request_type`, `bittorrent_dht.info_hash` |
| `smtp` | SMTP transactions | `smtp.helo`, `smtp.mail_from`, `smtp.rcpt_to` |
| `arp` | ARP requests/replies (decode-layer, not app-layer - disabled by default, see note below) | `arp.opcode`, `arp.src_mac`, `arp.dest_mac` |
| `log` | Imported log events (EVTX, JSON, CSV, XML, generic logs) | parsed dynamic fields (one column per log field) |
| `sigmaalert` | Sigma rule matches on imported logs | `rule_title`, `severity`, `level`, `original_log` |
| `protocol_decode` | Suricata's built-in protocol-command-decode alerts, reclassified out of `alert` - labeled "Decoder Alerts" in the UI (synthetic - see note below) | `alert.signature`, `alert.severity`, `alert.category`, `alert.rule` |
| `stats` | Suricata internal stats | (excluded from display) |

**Note on Suricata 8 / DNS logging:** this app now runs on Suricata 8.0.6
(upgraded from 7.0.10 via Debian's `trixie-backports`). `enip`/`ntp` eve
logging (previously unavailable - Suricata 7.0.10 had no output module for
either; see `_enable_eve_log_protocol_types` in `suricata_analyzer.py`) now
works for real, confirmed with a live NTP capture. Separately, and much more
importantly: **Suricata 8 changed DNS logging to a new "V3" format by
default** - `dns.rrname`/`dns.rrtype` (read directly by every DNS column/row/
detail case) no longer exist at the top level at all; the same info moved to
`dns.queries[0].rrname`/`rrtype`. This silently broke the `dns` tab entirely
under Suricata 8 until fixed (Query/Type both went blank) - one of the
highest-volume, most-viewed event types in the app. `mdns` (new in Suricata
8) uses this same `queries[]` array shape. Both `dns` and `mdns` now read the
array form, with `dns` also falling back to the old flat fields for any
previously-stored Suricata 7 analyses. Also new in 8: `websocket`, `pop3`,
`ldap` (all real app-layer protocols with proper eve loggers) and `arp` (a
new decode-layer packet logger, not app-layer). `arp` ships **disabled by
default** in Suricata's own config (comment: "Many events can be logged") -
unlike modbus/dnp3/enip/ntp/pgsql, this app doesn't force it on by default
either; it's a real volume/signal tradeoff on a live network that should be
a deliberate choice, not a silent default. Set the `ENABLE_ARP_LOGGING`
environment variable (see [Development Setup](../development-setup.md#environment-variables))
to opt in - `setup_suricata_config()`'s `enable_arp` parameter, wired to
that env var in `socrates.py`'s `main()`, calls `_enable_eve_log_arp` in
`suricata_analyzer.py` when set.

**Note on `protocol_decode`:** when the opt-in `show_protocol_decode_alerts`
setting (Rules modal) is enabled, Suricata's own built-in
protocol-command-decode detection rules stay active and generate real
`alert` events with `alert.category === "Generic Protocol Command Decode"`.
These are noise, not threat detections, so `create_sqlite_db` (`db.py`)
rewrites their `event_type` to `protocol_decode` at ingestion time, giving
them a dedicated tab (labeled "Decoder Alerts" in the UI - the internal
event_type/setting name intentionally stays `protocol_decode`/
`show_protocol_decode_alerts`, matching Suricata's own
"protocol-command-decode" classtype) instead of diluting `alert`. The
event otherwise keeps the exact same shape as `alert` (same fields, same
aggregation columns, same Detail-column logic) - the only differences are
the tab/label/color and that it has no Playbook section or AI Summary
field, since there's no investigation guidance (or rule explanation) needed
for something that isn't a real detection. When the
setting is off (the default), Suricata never generates this category at
all, so the tab never appears.

Note this is a related but distinct signal from the separate `anomaly`
event type above: Suricata's anomaly logger fires for every detected
protocol anomaly regardless of rule configuration, while `protocol_decode`
only fires when a specific built-in decoder *rule* matches - some anomaly
types (e.g. TLS `weak_crypto_*`) have no corresponding decoder rule at
all, and even for overlapping categories the counts don't match exactly.
Enabling `show_protocol_decode_alerts` therefore surfaces a second,
overlapping (not identical) view of much of the same underlying signal.
