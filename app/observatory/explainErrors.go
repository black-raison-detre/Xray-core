package observatory

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type errorCollector struct {
	mu     sync.Mutex
	errors *errors.Error
}

func (e *errorCollector) SubmitError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A reused connection can report asynchronously between probes. Retain
	// only its latest error, without mutating a previously returned report.
	e.errors = errors.New("underlying connection error").Base(err)
}

func (e *errorCollector) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = nil
}

func newErrorCollector() *errorCollector {
	return &errorCollector{}
}

func (e *errorCollector) UnderlyingError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.errors == nil {
		return errors.New("failed to produce report")
	}
	return e.errors
}
