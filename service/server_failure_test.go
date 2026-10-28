// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AthenZ/garm/v3/config"
)

func Test_server_ListenAndServe_TLSConfigurationFailure(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(config.Server{
		HealthzPath:      "/healthz",
		ShutdownDuration: "1s",
		ProbeWaitTime:    "0s",
		TLS: config.TLS{
			Enabled: true,
			Cert:    filepath.Join(dir, "missing.crt"),
			Key:     filepath.Join(dir, "missing.key"),
		},
	}, nil).(*server)
	s.srv.Addr = "127.0.0.1:0"
	s.hcsrv.Addr = "127.0.0.1:0"
	t.Cleanup(func() {
		if err := s.srv.Close(); err != nil {
			t.Errorf("close webhook server: %v", err)
		}
		if err := s.hcsrv.Close(); err != nil {
			t.Errorf("close health check server: %v", err)
		}
	})

	healthShutdown := make(chan struct{})
	s.hcsrv.RegisterOnShutdown(func() {
		close(healthShutdown)
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	select {
	case errs := <-s.ListenAndServe(ctx):
		foundMissingFile := false
		for _, err := range errs {
			if errors.Is(err, os.ErrNotExist) {
				foundMissingFile = true
				break
			}
		}
		if !foundMissingFile {
			t.Fatalf("ListenAndServe() errors = %v, want a missing TLS file error", errs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe() did not report the TLS startup failure")
	}

	select {
	case <-healthShutdown:
	case <-time.After(5 * time.Second):
		t.Fatal("health check server was not shut down after the TLS startup failure")
	}

	if err := s.hcsrv.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatalf("health check server ListenAndServe() = %v, want %v", err, http.ErrServerClosed)
	}
}
