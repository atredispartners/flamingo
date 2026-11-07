package cmd

import (
	"github.com/atredispartners/flamingo/pkg/flamingo"
	log "github.com/sirupsen/logrus"
)

// listenerSpawner starts one listener on the given port and returns its shutdown function.
type listenerSpawner func(port uint16) (shutdown func(), err error)

// startListeners spawns a listener for each port in the port specification.
func startListeners(name string, portSpec string, spawn listenerSpawner) {
	ports, err := flamingo.CrackPorts(portSpec)
	if err != nil {
		log.Fatalf("failed to process %s ports %s: %s", name, portSpec, err)
	}

	for _, port := range ports {
		shutdown, err := spawn(uint16(port))
		if err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start %s server on port %d: %q", name, port, err)
			} else {
				log.Errorf("failed to start %s server on port %d: %q", name, port, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, shutdown)
	}
}

func setupSMTP(rw *flamingo.RecordWriter) {
	startListeners("smtp", params.SMTPPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfSMTP()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnSMTP(conf)
	})
}

func setupSMTPS(rw *flamingo.RecordWriter) {
	startListeners("smtps", params.SMTPSPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfSMTP()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLS = true
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnSMTP(conf)
	})
}

func setupPOP3(rw *flamingo.RecordWriter) {
	startListeners("pop3", params.POP3Ports, func(port uint16) (func(), error) {
		conf := flamingo.NewConfPOP3()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnPOP3(conf)
	})
}

func setupPOP3S(rw *flamingo.RecordWriter) {
	startListeners("pop3s", params.POP3SPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfPOP3()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLS = true
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnPOP3(conf)
	})
}

func setupTelnet(rw *flamingo.RecordWriter) {
	startListeners("telnet", params.TelnetPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfTelnet()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnTelnet(conf)
	})
}

func setupMySQL(rw *flamingo.RecordWriter) {
	startListeners("mysql", params.MySQLPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfMySQL()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnMySQL(conf)
	})
}

func setupPostgres(rw *flamingo.RecordWriter) {
	startListeners("postgres", params.PostgresPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfPostgres()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnPostgres(conf)
	})
}

func setupMSSQL(rw *flamingo.RecordWriter) {
	startListeners("mssql", params.MSSQLPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfMSSQL()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnMSSQL(conf)
	})
}

func setupRedis(rw *flamingo.RecordWriter) {
	startListeners("redis", params.RedisPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfRedis()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnRedis(conf)
	})
}

func setupSOCKS(rw *flamingo.RecordWriter) {
	startListeners("socks", params.SOCKSPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfSOCKS()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnSOCKS(conf)
	})
}

func setupSIP(rw *flamingo.RecordWriter) {
	startListeners("sip", params.SIPPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfSIP()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnSIP(conf)
	})
}

func setupAMQP(rw *flamingo.RecordWriter) {
	startListeners("amqp", params.AMQPPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfAMQP()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnAMQP(conf)
	})
}

func setupAMQPS(rw *flamingo.RecordWriter) {
	startListeners("amqps", params.AMQPSPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfAMQP()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLS = true
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnAMQP(conf)
	})
}

func setupMongoDB(rw *flamingo.RecordWriter) {
	startListeners("mongodb", params.MongoDBPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfMongoDB()
		conf.BindPort = port
		conf.RecordWriter = rw
		return conf.Shutdown, flamingo.SpawnMongoDB(conf)
	})
}

func setupRDP(rw *flamingo.RecordWriter) {
	startListeners("rdp", params.RDPPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfRDP()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.TLSCert = params.TLSCertData
		conf.TLSKey = params.TLSKeyData
		conf.TLSName = params.TLSName
		return conf.Shutdown, flamingo.SpawnRDP(conf)
	})
}
