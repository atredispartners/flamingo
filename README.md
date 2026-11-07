# Flamingo 

A filter-feeding bird. Captures credentials sprayed across the network by various IT and security products.

Currently supports SSH, HTTP, LDAP, DNS, FTP, SNMP, VNC, IMAP, POP3, SMTP, Telnet, MySQL, PostgreSQL, MSSQL, Redis, MongoDB, AMQP, SOCKS, SIP, and RDP credential collection.

Pull requests are encouraged for additional protocols and output destinations.

## Protocols

| Protocol | Default ports | Options | Captures |
|----------|---------------|---------|----------|
| SSH | 22/tcp | `--ssh-ports`, `--ssh-host-key` | Passwords and public keys |
| HTTP/HTTPS | 80/tcp, 443/tcp | `--http-ports`, `--https-ports`, `--http-auth-mode`, `--http-realm` | Basic credentials or NTLM challenge/response |
| LDAP/LDAPS | 389/tcp, 636/tcp | `--ldap-ports`, `--ldaps-ports` | Simple bind credentials |
| DNS | 53/udp, 5353/udp | `--dns-ports`, `--dns-resolve-to` | Queries |
| FTP | 21/tcp | `--ftp-ports` | USER/PASS credentials |
| SNMP | 161/udp | `--snmp-ports` | Community strings |
| VNC | 5900/tcp | `--vnc-ports` | DES challenge/response (hashcat mode 14000, john `vnc`) |
| IMAP/IMAPS | 143/tcp, 993/tcp | `--imap-ports`, `--imaps-ports` | LOGIN, PLAIN, and SASL LOGIN credentials; CRAM-MD5 challenge/response (hashcat mode 10200) |
| POP3/POP3S | 110/tcp, 995/tcp | `--pop3-ports`, `--pop3s-ports` | USER/PASS, SASL PLAIN and LOGIN credentials; APOP digests; CRAM-MD5 challenge/response (hashcat mode 10200) |
| SMTP/SMTPS | 25/tcp, 587/tcp, 465/tcp | `--smtp-ports`, `--smtps-ports` | AUTH PLAIN and LOGIN credentials; CRAM-MD5 challenge/response (hashcat mode 10200); NTLM challenge/response (hashcat mode 5600) |
| Telnet | 23/tcp | `--telnet-ports` | Login prompt username/password attempts |
| MySQL | 3306/tcp | `--mysql-ports` | mysql_native_password challenge/response (hashcat mode 11200) and cleartext passwords via auth switch |
| PostgreSQL | 5432/tcp | `--postgres-ports` | Cleartext passwords (SSLRequest upgrades are honored) |
| MSSQL | 1433/tcp | `--mssql-ports` | TDS LOGIN7 username/password |
| Redis | 6379/tcp | `--redis-ports` | AUTH and HELLO credentials |
| MongoDB | 27017/tcp | `--mongodb-ports` | SASL PLAIN credentials; SCRAM-SHA-1/SCRAM-SHA-256 client proofs with the salt, nonces, and auth message |
| AMQP/AMQPS | 5672/tcp, 5671/tcp | `--amqp-ports`, `--amqps-ports` | PLAIN and AMQPLAIN credentials |
| SOCKS | 1080/tcp | `--socks-ports` | SOCKS4/4a user IDs and SOCKS5 username/password |
| SIP | 5060/udp | `--sip-ports` | Digest challenge/response (hashcat mode 11400) |
| RDP | 3389/tcp | `--rdp-ports` | CredSSP NTLM challenge/response (hashcat mode 5600) and cleartext Client Info passwords from TLS-only clients |

All protocols are enabled by default. The IMAP, POP3, and SMTP listeners advertise STARTTLS (STLS for POP3) and upgrade the session using the configured TLS certificate, so clients that refuse to authenticate in the clear still submit credentials. The MySQL and PostgreSQL listeners honor in-protocol TLS upgrade requests the same way, and the RDP listener terminates TLS for both NLA (CredSSP) and TLS-only clients.

The HTTPS, LDAPS, IMAPS, POP3S, SMTPS, AMQPS, RDP, and STARTTLS-capable listeners use a self-signed certificate unless `--tls-cert` and `--tls-key` are provided. The VNC, NTLM, CRAM-MD5, MySQL, SIP, and MongoDB SCRAM listeners present a fixed challenge, salt, or nonce so captured responses can be cracked offline.

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

The default is to log credentials to standard output and append to `flamingo.log` in the working directory.

## Options

Use `--protocols` to configure a comma-separated list of enabled protocol listeners. The default is `ssh,snmp,ldap,http,dns,ftp,vnc,imap,pop3,smtp,telnet,mysql,postgres,mssql,redis,mongodb,amqp,socks,sip,rdp`.

```
$ flamingo --protocols imap,ldap --imap-ports 143,1143 --ldap-ports 389
```

Use additional options to specify ports and protocol options for listeners. Port options accept comma-separated lists and ranges, such as `80,8000-8010`.

All additional command-line arguments are output destinations.

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
