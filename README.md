# Flamingo 

A filter-feeding bird. Captures credentials sprayed across the network by various IT and security products.

Currently supports SSH, HTTP, LDAP, DNS, FTP, SNMP, VNC, and IMAP credential collection.

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

All protocols are enabled by default. The IMAP listener advertises STARTTLS and upgrades the session using the configured TLS certificate, so clients that refuse to authenticate in the clear still submit credentials.

The HTTPS, LDAPS, IMAPS, and IMAP STARTTLS listeners use a self-signed certificate unless `--tls-cert` and `--tls-key` are provided. The VNC, NTLM, and CRAM-MD5 listeners present a fixed challenge so captured responses can be cracked offline.

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

Use `--protocols` to configure a comma-separated list of enabled protocol listeners. The default is `ssh,snmp,ldap,http,dns,ftp,vnc,imap`.

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
