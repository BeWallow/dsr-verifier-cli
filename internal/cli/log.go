package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// LogEntry is one JSON line appended to the audit log per verification attempt.
// The log is append-only and never read back by the CLI.
type LogEntry struct {
	Timestamp       string `json:"timestamp"`
	Command         string `json:"command"`
	File            string `json:"file"`
	Result          string `json:"result"`
	DurationMS      int64  `json:"duration_ms"`
	VerifierVersion string `json:"verifier_version"`
}

// DefaultLogFile is the log path used when --no-log is not set.
const DefaultLogFile = "verifier.log"

// WriteLogEntry appends a single JSON line to logPath.
// Errors are non-fatal: a log write failure is reported to stderr but does
// not change the exit code. Auditors can use --no-log to suppress logging
// when their environment restricts file writes.
func WriteLogEntry(logPath, command, file, result string, durationMS int64) error {
	entry := LogEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Command:         command,
		File:            file,
		Result:          result,
		DurationMS:      durationMS,
		VerifierVersion: Version,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}
	b = append(b, '\n')

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer f.Close()

	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write log file: %w", err)
	}
	return nil
}
