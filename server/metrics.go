package server

import (
	"sync"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

type Metrics struct {
	handler                       fasthttp.RequestHandler
	totalLogins                   prometheus.Counter
	totalFailedLogins             prometheus.Counter
	totalHydraLogins              prometheus.Counter
	totalHydraFailedLogins        prometheus.Counter
	totalSignups                  prometheus.Counter
	totalPasswordResets           prometheus.Counter
	totalPasswordResetsSent       prometheus.Counter
	totalAccountVerifications     prometheus.Counter
	totalAccountVerificationsSent prometheus.Counter
	groupExpiryFailures           prometheus.Counter
	forwardAuthRequests           *prometheus.CounterVec
	syncLastRun                   prometheus.Gauge
	syncLastSuccess               prometheus.Gauge
	syncChanges                   *prometheus.CounterVec
	syncHeld                      prometheus.Gauge
}

var (
	metricsOnce      sync.Once
	metricsSingleton *Metrics
)

// NewMetrics returns the process-wide metrics instance. Counters register
// with the global prometheus registry, which panics on duplicate
// registration — so this must be a singleton.
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsSingleton = newMetrics()
	})
	return metricsSingleton
}

func newMetrics() *Metrics {
	m := &Metrics{
		totalLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_logins_total",
			Help: "The total number of successful logins",
		}),
		totalFailedLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_logins_failed_total",
			Help: "The total number of failed logins",
		}),
		totalHydraLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_hydra_logins_total",
			Help: "The total number of successful Hydra logins",
		}),
		totalHydraFailedLogins: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_hydra_logins_failed_total",
			Help: "The total number of failed Hydra logins",
		}),
		totalSignups: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_signups_total",
			Help: "The total number of new accounts created",
		}),
		totalPasswordResets: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_password_reset_total",
			Help: "The total number of successfull password resets",
		}),
		totalPasswordResetsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_password_reset_sent_total",
			Help: "The total number of password reset emails sent",
		}),
		totalAccountVerifications: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_account_verification_total",
			Help: "The total number of successfull account verifications",
		}),
		totalAccountVerificationsSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_account_verification_sent_total",
			Help: "The total number of account verification emails sent",
		}),
		groupExpiryFailures: promauto.NewCounter(prometheus.CounterOpts{
			Name: "mokey_group_membership_expiry_failures_total",
			Help: "The total number of ended group memberships FreeIPA refused to remove",
		}),
		forwardAuthRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "mokey_forward_auth_requests_total",
			Help: "The total number of forward-auth verify requests by result (allowed, denied, unauthenticated)",
		}, []string{"result"}),
		syncLastRun: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "mokey_sync_last_run_timestamp_seconds",
			Help: "Unix time of the last directory sync run, dry runs excluded",
		}),
		syncLastSuccess: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "mokey_sync_last_success_timestamp_seconds",
			Help: "Unix time of the last directory sync run that finished without errors",
		}),
		syncChanges: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "mokey_sync_changes_total",
			Help: "The total number of changes directory sync applied, by kind",
		}, []string{"kind"}),
		syncHeld: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "mokey_sync_held",
			Help: "1 when the safety brake held the locks, deletes and group removals of the last directory sync run",
		}),
	}

	m.handler = fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())

	return m
}

func (m *Metrics) Handler(c fiber.Ctx) error {
	m.handler(c.RequestCtx())
	return nil
}
