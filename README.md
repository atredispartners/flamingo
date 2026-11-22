# Flamingo 

A filter-feeding bird. Captures credentials sprayed across the network by various IT and security products.

Currently supports SSH, HTTP, HTTP proxy, LDAP, DNS, FTP, SNMP, VNC, IMAP, POP3, SMTP, Telnet, MySQL, PostgreSQL, MSSQL, SQL Browser, Redis, MongoDB, AMQP, SOCKS, SIP, RDP, SMB, Kerberos, MSRPC, WinRM, ADWS, and MQTT credential collection, plus LLMNR, NBT-NS, and mDNS name services and optional NTLM relaying.

Pull requests are encouraged for additional protocols and output destinations.

## Protocols

| Protocol | Default ports | Options | Captures |
|----------|---------------|---------|----------|
| SSH | 22/tcp | `--ssh-ports`, `--ssh-host-key` | Passwords and public keys |
| HTTP/HTTPS | 80/tcp, 443/tcp | `--http-ports`, `--https-ports`, `--http-auth-mode`, `--http-realm`, `--http-wpad` | Basic credentials or NTLM challenge/response (hashcat mode 5600); optionally serves a WPAD file |
| LDAP/LDAPS | 389/tcp, 636/tcp | `--ldap-ports`, `--ldaps-ports` | Simple bind credentials, SASL PLAIN, SASL DIGEST-MD5, and NTLM/GSS-SPNEGO binds (hashcat mode 5600) |
| DNS | 53/udp | `--dns-ports`, `--dns-resolve-to` | Queries; answers A, AAAA, SOA, MX, TXT, SRV and ANY, mapping SRV service names to flamingo's own listeners |
| FTP | 21/tcp | `--ftp-ports` | USER/PASS credentials |
| SNMP | 161/udp | `--snmp-ports` | v1/v2c community strings and v3 USM authentication (hashcat modes 25000, 26700-27300) |
| VNC | 5900/tcp | `--vnc-ports` | DES challenge/response (hashcat mode 14000, john `vnc`) |
| IMAP/IMAPS | 143/tcp, 993/tcp | `--imap-ports`, `--imaps-ports` | LOGIN, PLAIN, and SASL LOGIN credentials; CRAM-MD5 challenge/response (hashcat mode 10200) |
| POP3/POP3S | 110/tcp, 995/tcp | `--pop3-ports`, `--pop3s-ports` | USER/PASS, SASL PLAIN and LOGIN credentials; APOP digests; CRAM-MD5 challenge/response (hashcat mode 10200) |
| SMTP/SMTPS | 25/tcp, 587/tcp, 465/tcp | `--smtp-ports`, `--smtps-ports` | AUTH PLAIN and LOGIN credentials; CRAM-MD5 challenge/response (hashcat mode 10200); NTLM challenge/response (hashcat mode 5600) |
| Telnet | 23/tcp | `--telnet-ports` | Login prompt username/password attempts |
| MySQL | 3306/tcp | `--mysql-ports` | mysql_native_password challenge/response (hashcat mode 11200) and cleartext passwords via auth switch |
| PostgreSQL | 5432/tcp | `--postgres-ports` | Cleartext passwords (SSLRequest upgrades are honored) |
| MSSQL | 1433/tcp | `--mssql-ports` | TDS LOGIN7 username/password, and NTLM from Windows Authentication (hashcat mode 5600) |
| Redis | 6379/tcp | `--redis-ports` | AUTH and HELLO credentials |
| MongoDB | 27017/tcp | `--mongodb-ports` | SASL PLAIN credentials; SCRAM-SHA-1/SCRAM-SHA-256 client proofs with the salt, nonces, and auth message |
| AMQP/AMQPS | 5672/tcp, 5671/tcp | `--amqp-ports`, `--amqps-ports` | PLAIN and AMQPLAIN credentials |
| SOCKS | 1080/tcp | `--socks-ports` | SOCKS4/4a user IDs and SOCKS5 username/password |
| SIP | 5060/udp | `--sip-ports` | Digest challenge/response (hashcat mode 11400) |
| RDP | 3389/tcp | `--rdp-ports` | CredSSP NTLM challenge/response (hashcat mode 5600) and cleartext Client Info passwords from TLS-only clients |
| SMB | 445/tcp, 139/tcp | `--smb-ports` | NTLMv2 (hashcat mode 5600) and NTLMv1 (hashcat mode 5500) from SMB1, SMB2 and SMB3 session setup |
| Kerberos | 88/tcp, 88/udp | `--kerberos-ports`, `--kerberos-force-ntlm` | AS-REQ pre-authentication timestamps (hashcat modes 7500, 19800, 19900) |
| MSRPC | 135/tcp | `--msrpc-ports` | NTLM from DCE/RPC bind authentication (hashcat mode 5600); answers `IObjectExporter::ServerAlive2` so a DCOM client that pings first goes on to authenticate |
| WinRM | 5985/tcp, 5986/tcp | `--winrm-ports`, `--winrms-ports` | NTLM over WS-Management on `/wsman` (hashcat mode 5600) |
| ADWS | 9389/tcp | `--adws-ports` | NTLM from Active Directory Web Services (hashcat mode 5600) |
| SQL Browser | 1434/udp | `--mssql-browser-ports`, `--poison-broadcast` | Instance discovery requests; answers point clients at the MSSQL listener. Discovery is usually broadcast to the segment, so answering it needs `--poison-broadcast` |
| HTTP proxy | 3128/tcp | `--http-proxy-ports` | Proxy credentials via 407 (NTLM hashcat mode 5600, or Basic). `--http-wpad` is served by the HTTP/HTTPS listeners and points clients here |
| MQTT | 1883/tcp | `--mqtt-ports` | CONNECT username and password |
| LLMNR | 5355/udp | `--llmnr-ports`, `--poison-*` | Name queries; answers with this host's address |
| NBT-NS | 137/udp | `--nbtns-ports`, `--poison-*` | Name queries; answers with this host's address |
| mDNS | 5353/udp | `--mdns-ports`, `--poison-*` | Name queries; answers with this host's address |

All protocols are enabled by default. The SMB listener negotiates dialects 2.0.2 through 3.1.1 and answers SMB1 clients with NT LM 0.12, so it collects NTLMv2 from modern Windows and LM/NTLMv1 from legacy clients. It never signs: a client that requires signing still completes session setup, which is where the credential is, and drops the session afterwards. The IMAP, POP3, and SMTP listeners advertise STARTTLS (STLS for POP3) and upgrade the session using the configured TLS certificate, so clients that refuse to authenticate in the clear still submit credentials. The MySQL and PostgreSQL listeners honor in-protocol TLS upgrade requests the same way, and the RDP listener terminates TLS for both NLA (CredSSP) and TLS-only clients.

The HTTPS, LDAPS, IMAPS, POP3S, SMTPS, AMQPS, WinRM over TLS (5986), RDP, and STARTTLS-capable listeners use a self-signed certificate unless `--tls-cert` and `--tls-key` are provided. The VNC, NTLM, CRAM-MD5, MySQL, SIP, SMB, and MongoDB SCRAM listeners present a fixed challenge, salt, or nonce so captured responses can be cracked offline; the Kerberos listener returns the standard `realm+cname` salt, which is derived rather than fixed but equally predictable. The NTLM challenge is `1122334455667788` on every listener that uses one.

Every listener runs on every supported platform. The listeners that take NTLM from an
unauthenticated peer — SMB, MSRPC, ADWS and WinRM — are flamingo's own code rather than
wrappers over gopacket's protocol servers, whose NTLM parsing does length arithmetic that
panics where `int` is 32 bits; that is what keeps the `386` and `arm` builds usable. It is
not a blanket rule about libraries: DNS is served by miekg/dns, SNMP decodes with gosnmp,
and LDAP parses with the in-tree BER fork.

## Name poisoning

The LLMNR, NBT-NS, and mDNS listeners run by default and behave like every other
flamingo listener: they observe and log name queries, and they answer queries sent
directly to this host, pointing the querier at flamingo's own address so it
authenticates to the collectors above.

Answering queries that were *multicast or broadcast to the whole segment* is a
different thing. That is poisoning: responding on behalf of names that were never
addressed to this host, and redirecting traffic that was not meant for it. It is off
unless you ask for it:

```
$ flamingo --poison-broadcast
```

Only use it on networks you are authorized to test. Queries are logged either way, so
you can see what a poisoning run would have caught before enabling it, and
`--poison-analyze` keeps the listeners observing without poisoning anything.

The scope controls govern poisoning — the broadcast and multicast answers. They do not
restrict replies to queries addressed to this host, because answering those is not
poisoning: it is this host replying to traffic aimed at it, exactly as the SMB or HTTP
listener replies to a connection. Worth setting on any real engagement:

| Option | Effect |
|--------|--------|
| `--poison-respond-to` | Only poison broadcast queries from these addresses (IP, CIDR, or range) |
| `--poison-dont-respond-to` | Never poison broadcast queries from these addresses |
| `--poison-respond-to-name` | Only poison these queried names |
| `--poison-dont-respond-to-name` | Never poison these queried names (default `ISATAP`) |
| `--poison-dont-respond-to-tld` | Never poison names with these suffixes (default `_dosvc`) |
| `--poison-analyze` | Observe and log broadcast queries without poisoning them |
| `--poison-spoof-ip`, `--poison-spoof-ip6` | Answer with this address instead of our own |
| `--poison-ttl` | Override the answer TTL, which defenders fingerprint |

By default the answer carries this host's own address on the interface the query arrived
on, so no configuration is needed on a single-homed host.

## NTLM relay

Flamingo can forward a captured NTLM authentication to another host, authenticating
there as the victim, rather than only recording the hash. This is off unless you name
somewhere to send it:

```
$ flamingo --relay-targets smb://10.0.0.5,ldaps://dc01.corp.local
```

With no `--relay-targets`, no relaying happens anywhere and every listener stays
capture-only. With targets set, the default action is still conservative: authenticate,
report whether the target accepted it and at what privilege, and disconnect. Post-relay
modules are each opt-in by name:

```
$ flamingo --relay-targets smb://10.0.0.5 --relay-attack secretsdump
```

Relaying is supported from the SMB, MSRPC, WinRM and ADWS listeners. Schemes accepted by
`--relay-targets` are `smb`, `ldap`, `ldaps`, `http`, `https`, `mssql`, `winrm`, `winrms`
and `rpc`; a bare host means `smb`. Other options are `--relay-attack`,
`--relay-one-shot`, `--relay-random-target` and `--relay-timeout`.

Each attempt produces a `_type: relay` record alongside the usual credential, so you can
tell the three cases apart: `relayed: true` with `outcome: success` (the target accepted
it), `relayed: true` with `outcome: rejected` or `signing-required`, and `relayed: false`
with `outcome: unreachable` or `no-target`. The credential is recorded either way.

Two limits are worth knowing before you rely on this:

* **A relayed session cannot be signed.** There is no session key for a relayed
  authentication, and the relay client negotiates at most SMB 3.0. A target that requires
  signing will accept the authentication and then refuse to serve the session; flamingo
  reports that as `signing-required` rather than a generic failure.
* **A target on this host is refused at startup**, as is one on a port flamingo is
  listening on. Relaying a victim back into flamingo captures nothing new and loops.

Relaying authenticates to a third party as someone else. Only use it where you are
authorized to do so.

## Usage

1. Obtain the flamingo binary from the [releases](https://github.com/atredispartners/flamingo/releases) page or build from source.

```
$ GOOS=windows GOARCH=amd64 go build -o flamingo.exe
```

```
$ go install github.com/atredispartners/flamingo@latest && \
  $GOPATH/bin/flamingo
```

2. Run the binary and collect credentials
```
C:\> flamingo.exe

{"_etime":"2020-01-10T17:56:51Z","_host":"1.2.3.4:18301","_proto":"ssh","method":"pubkey","pubkey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPVSxqrWfNle0nnJrKS3NA12uhu9PHxnP4OlD843tRz/","pubkey-sha256":"SHA256:/7UkXjk0XtBe9N6RrAGGgJTGuKKi1Hgk3E+4TPo54Cw","username":"devuser","version":"SSH-2.0-OpenSSH_for_Windows_7.7"}

{"_etime":"2020-01-10T17:56:52Z","_host":"1.2.3.4:1361","_proto":"ssh","method":"password","password":"SuperS3kr3t^!","username":"root","version":"SSH-2.0-OpenSSH_for_Windows_7.7"}

{"_etime":"2020-01-10T17:56:53Z","_host":"1.2.3.4:9992","_proto":"ssh","method":"password","password":"DefaultPotato","username":"vulnscan-a","version":"SSH-2.0-OpenSSH_for_Windows_7.7"}

```

Every record carries `_etime`, `_type` (`credential`, `access`, `query`, `relay` or
`relay_attack`),
`_proto`, `_host` (the client) and `_server` (the listener it reached), plus whatever the
protocol yielded. A captured SMB authentication looks like this, with the hash trimmed for
width:

```
{"_etime":"2026-11-21T18:49:58-06:00","_host":"10.0.0.51:49707","_proto":"smb",
 "_server":"0.0.0.0:445","_type":"credential","client_version":"10.0.0",
 "dialect":"3.1.1","domain":"CORP","hashcat":"victim::CORP:1122334455667788:40c9653a...",
 "hashcat_mode":"5600","ntlm_version":"v2","username":"victim","workstation":""}
```

The `hashcat` field is ready to crack as-is; `hashcat_mode` names the mode to use.

The default is to log credentials to standard output and append to `flamingo.log` in the working directory.

## Options

Use `--protocols` to configure a comma-separated list of enabled protocol listeners. The default is:

```
ssh,snmp,ldap,http,http-proxy,mqtt,dns,ftp,vnc,imap,pop3,smtp,telnet,mysql,postgres,
mssql,mssql-browser,redis,mongodb,amqp,socks,sip,rdp,smb,kerberos,msrpc,winrm,adws,
llmnr,nbtns,mdns
```

```
$ flamingo --protocols imap,ldap --imap-ports 143,1143 --ldap-ports 389
```

Use additional options to specify ports and protocol options for listeners. Port options accept comma-separated lists and ranges, such as `80,8000-8010`.

All additional command-line arguments are output destinations.

### General options

| Option | Effect |
|--------|--------|
| `-v`, `--verbose` | Verbose output, including diagnostics from bundled protocol libraries |
| `-q`, `--quiet` | Hide startup banners and other extraneous output |
| `--dont-ignore` | Treat a listener that fails to start as fatal, instead of logging and continuing |
| `--tls-cert`, `--tls-key` | Certificate and key for the TLS listeners; a self-signed one is generated otherwise |
| `--tls-name` | Server name for generated certificates (default `localhost`) |
| `--tls-org` | Organization for generated certificates (default `Flamingo Feed, Inc.`) |

A few protocol options did not fit the tables above: `--wpad-proxy` overrides the
host or `host:port` a served WPAD file advertises, and `--poison-answer-name` overrides
the name used in an LLMNR answer record.

## Outputs

Flamingo can write recorded credentials to a variety of output formats. By default, flamingo will log to `flamingo.log` and standard output.

### Standard Output

Specifying `-` or `stdout` will result in flamingo only logging to standard output.

### File Destinations

Specifying one or more file paths will result in flamingo appending to these files.

### HTTP Destinations

Specifying HTTP or HTTPS URLs will result in flamingo sending a webhook POST request to each endpoint.

By default, this format supports platforms like Slack and Mattermost that support inbound webhooks.

The actual HTTP POST looks like:

```
POST /specified-url
Content-Type: application/json
User-Agent: flamingo/v0.0.0

{"text": "full-json-output of credential report"}
```

### Syslog Destinations

Specifying `syslog` or `syslog:<parameters>` will result in flamingo sending credentials to a syslog server.

The following formats are supported:

 * syslog - send to the default syslog output, typically a unix socket
 * syslog:unix:/dev/log - send to a specific unix stream socket
 * syslog:host - send to the specified host using udp and port 514
 * syslog:host:port - send to the specified host using udp and the specified port
 * syslog:udp:host - send to the specified host using udp and port 514
 * syslog:udp:host:port - send to the specified host using udp and the specified port
 * syslog:tcp:host - send to the specified host using tcp and port 514
 * syslog:tcp:host:port - send to the specified host using tcp and the specified port
 * syslog:tcp+tls:host - send to the specified host using tls over tcp and port 514
 * syslog:tcp+tls:host:port - send to the specified host using tls over tcp and the specified port

## Credits

 * Flamingo is developed and maintained by [HD Moore](https://github.com/hdm) and [Tom Steele](https://github.com/tomsteele)
 * Initial requirements by [Chris Bellows](https://github.com/chris-atredis)
 * NTLM support for HTTP by [Alex Flores](https://github.com/audibleblink)
 * VNC and IMAP support by [latentwhisper](https://github.com/latentwhisper)

## Third-party software and licensing

Flamingo is BSD 2-Clause licensed; see [LICENSE](LICENSE). Dependencies and their
licenses are listed in [NOTICE](NOTICE).

The SMB listener is built on the exported `x/wire` codecs from
[go-smb2](https://github.com/hirochachacha/go-smb2) (BSD 3-Clause) by Hiroshi Ioka. The
relay clients and every post-relay attack module come from
[gopacket](https://github.com/mandiant/gopacket) (Apache-2.0) by Mandiant. Both are
ordinary module dependencies — no source from either project is copied into this tree.

The name-poisoning listeners cover much of what
[Responder](https://github.com/lgandx/Responder) does, but share no code with it.
Responder is GPL-3.0, which is incompatible with this project's license, so LLMNR,
NBT-NS, and mDNS were implemented from their RFCs instead. See [NOTICE](NOTICE).
