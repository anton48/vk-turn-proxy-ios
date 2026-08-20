package speedtest

import (
	"net/http"
	"testing"
)

// Divergence 4 (../FORK.md): New() must give each client its OWN *http.Client.
//
// Unlike divergences 1-3 this one CAN be caught by value, and is — a source scan
// would be ceremony here (the fork is one token). The three assertions below were
// each seen RED under their own sabotage before being committed:
//
//	S1  restore `doer: http.DefaultClient`     -> all three fail
//	S2  delete `s.doer.Transport = s`          -> only OwnTransportSurvives fails
//
// 🚨 ProcessDefaultUntouched is decided at PACKAGE INIT, before any test body
// runs, by `var defaultClient = New()`. Do not "simplify" it by deleting the
// New() calls in the other subtests — and do not reorder it expecting the calls
// below to be what sets it.
func TestForkNewDoesNotShareTheProcessDefaultClient(t *testing.T) {
	t.Run("ProcessDefaultUntouched", func(t *testing.T) {
		// The package's own init constructs a client. If New() still aliased the
		// global, that alone would have installed a *Speedtest as the process's
		// default transport — for every unrelated http.Get in the host app.
		if tr := http.DefaultClient.Transport; tr != nil {
			t.Errorf("http.DefaultClient.Transport is %T, want nil: importing this package "+
				"must not rewire the process-wide client — see ../FORK.md divergence 4", tr)
		}
	})

	t.Run("InstancesDoNotShareAClient", func(t *testing.T) {
		a, b := New(), New()
		if a.doer == b.doer {
			t.Error("two clients share one *http.Client, so configuring either reconfigures both")
		}
		if a.doer == http.DefaultClient || b.doer == http.DefaultClient {
			t.Error("a client is using http.DefaultClient")
		}
	})

	t.Run("OwnTransportSurvivesAnotherConstruction", func(t *testing.T) {
		a := New()
		before := a.doer.Transport
		if before == nil {
			t.Fatal("a client was built with no Transport — it would silently fall back to " +
				"http.DefaultTransport, losing the dialer, the User-Agent and the HTTP/2 setting")
		}
		_ = New() // the second construction must not touch the first
		if a.doer.Transport != before {
			t.Error("constructing another client re-pointed the transport of a live one; " +
				"a measurement in flight would change engines mid-phase")
		}
	})
}
