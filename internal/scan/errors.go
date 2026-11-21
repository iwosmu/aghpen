// Package scan implements model.Engine: it plans chunks, runs the probe
// stages on a worker pool under one packet budget, collects HTTP/TLS data
// and signature matches, retries unstable hosts, and stops cleanly when the
// scan window closes.
package scan

import (
	"errors"

	"github.com/iwosmu/aghpen/internal/model"
)

// Pass one of the ErrPause* values as the cause of context.WithCancelCause
// to make Run return RunPaused with the matching PauseReason. Any other
// cancellation returns RunCancelled.
var (
	// ErrEmergencyStop is returned when the safety policy has the emergency stop set.
	ErrEmergencyStop = errors.New("scan: emergency stop is active, no run may start")
	// ErrPauseManual pauses a run on an operator's request.
	ErrPauseManual = errors.New("scan: paused by an operator")
	// ErrPauseEmergency pauses a running run when the emergency stop is pressed.
	ErrPauseEmergency = errors.New("scan: paused by the emergency stop")
	// ErrPauseWindow pauses a run because its time window closed.
	ErrPauseWindow = errors.New("scan: the scan window closed")
)

// PauseCause maps a model.Pause* reason to the cancel cause to use.
func PauseCause(reason string) error {
	switch reason {
	case model.PauseManual:
		return ErrPauseManual
	case model.PauseEmergency:
		return ErrPauseEmergency
	case model.PauseWindowClosed:
		return ErrPauseWindow
	}
	return nil
}

// pauseReason maps a cancel cause back to a pause reason.
func pauseReason(cause error) (string, bool) {
	switch {
	case errors.Is(cause, ErrPauseManual):
		return model.PauseManual, true
	case errors.Is(cause, ErrPauseEmergency):
		return model.PauseEmergency, true
	case errors.Is(cause, ErrPauseWindow):
		return model.PauseWindowClosed, true
	}
	return "", false
}
