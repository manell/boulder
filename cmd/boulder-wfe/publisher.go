package main

import (
	"os"

	ct "github.com/google/certificate-transparency/go"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/publisher"
)

type PUConfig struct {
	Publisher struct {
		cmd.ServiceConfig
		SubmissionTimeout              cmd.ConfigDuration
		MaxConcurrentRPCServerRequests int64
		SAService                      *cmd.GRPCClientConfig
		Features                       map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		CT struct {
			Logs                       []cmd.LogDescription
			IntermediateBundleFilename string
		}
	}
}

func NewPublisher() *publisher.Impl {
	configFile := "./publisher.json"

	var c PUConfig
	err := cmd.ReadConfigFile(configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Publisher.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "Publisher")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	logs := make([]*publisher.Log, len(c.Common.CT.Logs))
	for i, ld := range c.Common.CT.Logs {
		logs[i], err = publisher.NewLog(ld.URI, ld.Key, logger)
		cmd.FailOnError(err, "Unable to parse CT log description")
	}

	if c.Common.CT.IntermediateBundleFilename == "" {
		logger.AuditErr("No CT submission bundle provided")
		os.Exit(1)
	}
	pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
	cmd.FailOnError(err, "Failed to load CT submission bundle")
	bundle := []ct.ASN1Cert{}
	for _, cert := range pemBundle {
		bundle = append(bundle, ct.ASN1Cert(cert.Raw))
	}

	// TODO(jsha): Publisher is currently configured in production using old-style
	// GRPC config fields. Remove this once production is switched over.
	if c.Publisher.GRPC != nil && c.Publisher.TLS.CertFile == nil {
		c.Publisher.TLS = cmd.TLSConfig{
			CertFile:   &c.Publisher.GRPC.ServerCertificatePath,
			KeyFile:    &c.Publisher.GRPC.ServerKeyPath,
			CACertFile: &c.Publisher.GRPC.ClientIssuerPath,
		}
	}

	pubi := publisher.New(
		bundle,
		logs,
		c.Publisher.SubmissionTimeout.Duration,
		logger,
		scope,
		NewSA())

	return pubi
}
