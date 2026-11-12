package proxy

import "testing"

// The ONE predicate whoever listens to pion asks — the native session and the
// bridge's csqtt 2.5 relay: a permission refresh the relay answered 400, by
// pion's prefix AND the error-code form.
func TestRelayHoldsNoAllocationIsThePermissionRefreshAnswered400(t *testing.T) {
	for _, c := range []struct {
		msg  string
		want bool
	}{
		{"Fail to refresh permissions: CreatePermission error response (error 400: Bad Request)", true},
		{"Fail to refresh permissions: all retransmissions failed for the request", false},
		{"Fail to refresh permissions: CreatePermission error response (error 403: Forbidden), port 400", false},
		{"CreatePermission error response (error 400: Bad Request)", false},
		{"Failed to refresh allocation: Refresh error response (error 437: Allocation Mismatch)", false},
		{"", false},
	} {
		if got := RelayHoldsNoAllocation(c.msg); got != c.want {
			t.Errorf("RelayHoldsNoAllocation(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}
