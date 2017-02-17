package main

import (
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

type SAConfig struct {
	SA struct {
		cmd.ServiceConfig
		cmd.DBConfig

		MaxConcurrentRPCServerRequests int64

		Features map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func NewSA() *sa.SQLStorageAuthority {
	configFile := "./sa.json"

	var c SAConfig
	err := cmd.ReadConfigFile(configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.SA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "SA")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	saConf := c.SA

	dbURL, err := saConf.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")

	dbMap, err := sa.NewDbMap(dbURL, saConf.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Couldn't connect to SA database")

	go sa.ReportDbConnCount(dbMap, scope)

	sai, err := sa.NewSQLStorageAuthority(dbMap, clock.Default(), logger)
	cmd.FailOnError(err, "Failed to create SA impl")

	return sai
}
