package main

import (
	"fmt"
	"net/http"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/wfe"
)

const clientName = "WFE"

type config struct {
	WFE struct {
		cmd.ServiceConfig
		BaseURL          string
		ListenAddress    string
		TLSListenAddress string

		ServerCertificatePath string
		ServerKeyPath         string

		AllowOrigins []string

		CertCacheDuration           cmd.ConfigDuration
		CertNoCacheExpirationWindow cmd.ConfigDuration
		IndexCacheDuration          cmd.ConfigDuration
		IssuerCacheDuration         cmd.ConfigDuration

		ShutdownStopTimeout cmd.ConfigDuration
		ShutdownKillTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		AcceptRevocationReason bool
		AllowAuthzDeactivation bool

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool
	}

	Statsd cmd.StatsdConfig

	SubscriberAgreementURL string

	Syslog cmd.SyslogConfig

	Common struct {
		BaseURL    string
		IssuerCert string
	}
}

func main() {
	configFile := "./wfe.json"
	var c config
	err := cmd.ReadConfigFile(configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.WFE.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "WFE")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	wfe, err := wfe.NewWebFrontEndImpl(scope, clock.Default(), goodkey.NewKeyPolicy(), logger)
	cmd.FailOnError(err, "Unable to create WFE")

	wfe.RA = NewRA()
	wfe.SA = NewSA()

	// TODO: remove this check once the production config uses the SubscriberAgreementURL in the wfe section
	if c.WFE.SubscriberAgreementURL != "" {
		wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	} else {
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL
	}

	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.AcceptRevocationReason = c.WFE.AcceptRevocationReason
	wfe.AllowAuthzDeactivation = c.WFE.AllowAuthzDeactivation

	wfe.CertCacheDuration = c.WFE.CertCacheDuration.Duration
	wfe.CertNoCacheExpirationWindow = c.WFE.CertNoCacheExpirationWindow.Duration
	wfe.IndexCacheDuration = c.WFE.IndexCacheDuration.Duration
	wfe.IssuerCacheDuration = c.WFE.IssuerCacheDuration.Duration

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", goodkey.NewKeyPolicy()))

	// Set up paths
	wfe.BaseURL = c.Common.BaseURL
	h := wfe.Handler()

	http.ListenAndServe(":1234", h)
}
