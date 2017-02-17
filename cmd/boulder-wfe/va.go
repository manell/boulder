package main

import (
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cdr"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/va"
)

type VAConfig struct {
	VA struct {
		cmd.ServiceConfig

		UserAgent string

		IssuerDomain string

		PortConfig cmd.PortConfig

		MaxConcurrentRPCServerRequests int64

		GoogleSafeBrowsing *cmd.GoogleSafeBrowsingConfig

		CAADistributedResolver *cmd.CAADistributedResolverConfig

		// The number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries int

		// Feature flag to enable enforcement of CAA SERVFAILs.
		CAASERVFAILExceptions string

		Features map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}
}

func NewVA() *va.ValidationAuthorityImpl {
	configFile := "./va.json"

	var c VAConfig
	err := cmd.ReadConfigFile(configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.VA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "VA")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	pc := &cmd.PortConfig{
		HTTPPort:  80,
		HTTPSPort: 443,
		TLSPort:   443,
	}
	if c.VA.PortConfig.HTTPPort != 0 {
		pc.HTTPPort = c.VA.PortConfig.HTTPPort
	}
	if c.VA.PortConfig.HTTPSPort != 0 {
		pc.HTTPSPort = c.VA.PortConfig.HTTPSPort
	}
	if c.VA.PortConfig.TLSPort != 0 {
		pc.TLSPort = c.VA.PortConfig.TLSPort
	}

	var sbc va.SafeBrowsing
	// If the feature flag is set, use the Google safebrowsing library that
	// implements the v4 api instead of the legacy letsencrypt fork of
	// go-safebrowsing-api
	if features.Enabled(features.GoogleSafeBrowsingV4) {
		sbc, err = newGoogleSafeBrowsingV4(c.VA.GoogleSafeBrowsing, logger)
	} else {
		sbc, err = newGoogleSafeBrowsing(c.VA.GoogleSafeBrowsing)
	}
	cmd.FailOnError(err, "Failed to create Google Safe Browsing client")

	var cdrClient *cdr.CAADistributedResolver
	if c.VA.CAADistributedResolver != nil {
		var err error
		cdrClient, err = cdr.New(
			scope,
			c.VA.CAADistributedResolver.Timeout.Duration,
			c.VA.CAADistributedResolver.MaxFailures,
			c.VA.CAADistributedResolver.Proxies,
			logger)
		cmd.FailOnError(err, "Failed to create CAADistributedResolver")
	}

	dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse DNS timeout")
	dnsTries := c.VA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	clk := clock.Default()
	caaSERVFAILExceptions, err := bdns.ReadHostList(c.VA.CAASERVFAILExceptions)
	cmd.FailOnError(err, "Couldn't read CAASERVFAILExceptions file")
	var resolver bdns.DNSResolver
	if !c.Common.DNSAllowLoopbackAddresses {
		r := bdns.NewDNSResolverImpl(
			dnsTimeout,
			[]string{c.Common.DNSResolver},
			caaSERVFAILExceptions,
			scope,
			clk,
			dnsTries)
		resolver = r
	} else {
		r := bdns.NewTestDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver}, scope, clk, dnsTries)
		resolver = r
	}

	vai := va.NewValidationAuthorityImpl(
		pc,
		sbc,
		cdrClient,
		resolver,
		c.VA.UserAgent,
		c.VA.IssuerDomain,
		scope,
		clk,
		logger)

	return vai
}