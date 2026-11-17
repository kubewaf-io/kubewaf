/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"fmt"
	"strings"
	"time"
)

// MaxReloadGeneration caps how many times a missing Include file is retried.
const MaxReloadGeneration = 90

// LoadState is Envoy's last attempt to initialize the dynamic module.
type LoadState string

const (
	// LoadUnknown means neither status nor the envoy log shows an attempt yet.
	LoadUnknown LoadState = "unknown"
	// LoadRejected means the latest attempt failed to read an Include file.
	LoadRejected LoadState = "rejected"
	// LoadCandidate means the latest attempt logged a module load and no rejection after it.
	LoadCandidate LoadState = "candidate"
)

// MarkerWithGeneration appends a retry count so Envoy treats the filter config as new.
// Generation 0 is the content hash alone.
func MarkerWithGeneration(base string, generation int32) string {
	if generation <= 0 {
		return base
	}
	return fmt.Sprintf("%sr%d", base, generation)
}

// ObserveLoad reads the envoy container log first. A Gateway or
// EnvoyExtensionPolicy condition is used only when the log has no attempt yet.
// A stale status line must not hide a later successful load: Envoy Gateway
// keeps the previous listener, so Programmed can stay True across a rejection.
func ObserveLoad(statusMessages []string, envoyLog string) (LoadState, string) {
	if state, msg, ok := observeLog(envoyLog); ok {
		return state, msg
	}
	for _, msg := range statusMessages {
		if includeRejected(msg) {
			return LoadRejected, oneLine(msg)
		}
	}
	return LoadUnknown, ""
}

func observeLog(envoyLog string) (LoadState, string, bool) {
	lastLoad, lastFail, fail := -1, -1, ""
	for i, line := range strings.Split(envoyLog, "\n") {
		switch {
		case strings.Contains(line, "Dynamic module ABI") || (strings.Contains(line, "dynamic module") && strings.Contains(line, "loaded")):
			lastLoad = i
		case includeRejected(line):
			lastFail = i
			fail = line
		}
	}
	if lastFail >= 0 && lastFail >= lastLoad {
		return LoadRejected, oneLine(fail), true
	}
	if lastLoad >= 0 {
		return LoadCandidate, "", true
	}
	return LoadUnknown, "", false
}

func includeRejected(s string) bool {
	l := strings.ToLower(s)
	if strings.Contains(l, "failed to readfile") || strings.Contains(l, "no such file or directory") {
		return true
	}
	if strings.Contains(l, "failed to initialize dynamic module") || strings.Contains(l, "failed to load configuration") {
		return true
	}
	return strings.Contains(l, "config rejected") && strings.Contains(l, "dynamic module")
}

// RejectTime parses the envoy log timestamp at the start of a rejection line.
func RejectTime(msg string) (time.Time, bool) {
	start := strings.Index(msg, "[")
	end := strings.Index(msg, "]")
	if start < 0 || end <= start {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15:04:05.000", msg[start+1:end])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
