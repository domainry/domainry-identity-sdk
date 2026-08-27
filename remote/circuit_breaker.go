package remote

import (
	"sync"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

type availabilityCircuitBreaker struct {
	mu          sync.Mutex
	policy      CircuitBreakerPolicy
	clock       identity.Clock
	failures    int
	openedUntil time.Time
	probeActive bool
}

func newAvailabilityCircuitBreaker(policy CircuitBreakerPolicy, clock identity.Clock) *availabilityCircuitBreaker {
	return &availabilityCircuitBreaker{policy: policy, clock: clock}
}

func (breaker *availabilityCircuitBreaker) Allow() bool {
	if breaker == nil {
		return true
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	now := breaker.clock.Now()
	if breaker.openedUntil.IsZero() {
		return true
	}
	if now.Before(breaker.openedUntil) || breaker.probeActive {
		return false
	}
	breaker.probeActive = true
	return true
}

func (breaker *availabilityCircuitBreaker) Observe(failed bool) {
	if breaker == nil {
		return
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	if !failed {
		breaker.failures = 0
		breaker.openedUntil = time.Time{}
		breaker.probeActive = false
		return
	}
	if breaker.probeActive || breaker.failures+1 >= breaker.policy.FailureThreshold {
		breaker.failures = breaker.policy.FailureThreshold
		breaker.openedUntil = breaker.clock.Now().Add(breaker.policy.OpenDuration)
		breaker.probeActive = false
		return
	}
	breaker.failures++
}
