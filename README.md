# Flamingo 

A filter-feeding bird. Captures credentials sprayed across the network by various IT and security products.

Currently supports SSH, HTTP, LDAP, and SNMP credential collection.

## Usage

1. Obtain the flamingo binary from [releases](https://github.com/atredispartners/flamingo/releases) page or build from source.

```
$ GOOS=win32 GOARCH=amd64 go build -o flamingo.exe
```

```
$ go get -u -v github.com/atredispartners/flamingo && \
  go install -v github.com/atredispartners/flamingo && \
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

Use `--protocols` to configure a list of enabled protocol listeners

Use additional options to specify ports and protocol options for listeners.

All additional command-line arguments are output destinations.

Supported outputs:

 * `-` or no arguments results in output being written to standard output
 * http://[url] or https://[url] will deliver results via webhook (slack, mattermost, etc)
 * anything else is treated as an output file name


## Credits

 * Initial requirements by [Chris Bellows](https://github.com/chris-atredis)
 * Project creation and maintenance by [HD Moore](https://github.com/hdm)
 * NTLM support for HTTP by [Alex Flores](https://github.com/audibleblink)
