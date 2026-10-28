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
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCertReloaderMissingCA(t *testing.T) {
	dir := t.TempDir()
	reloader, err := NewCertReloader(CertReloaderCfg{
		CertPath: filepath.Join(dir, "missing.crt"),
		KeyPath:  filepath.Join(dir, "missing.key"),
		CaPath:   filepath.Join(dir, "missing-ca.pem"),
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewCertReloader() error = %v, want a missing CA file error", err)
	}
	if reloader != nil {
		t.Fatal("NewCertReloader() returned a reloader despite the missing configured CA")
	}
}

func TestCertReloaderPreservesCacheOnRefreshFailure(t *testing.T) {
	dir := t.TempDir()
	cached := &tls.Certificate{}
	mtime := time.Unix(1, 0)
	reloader := &CertReloader{
		certPath: filepath.Join(dir, "missing.crt"),
		keyPath:  filepath.Join(dir, "missing.key"),
		cert:     cached,
		mtime:    mtime,
	}

	if err := reloader.loadLocalCertAndKey(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadLocalCertAndKey() error = %v, want a missing certificate file error", err)
	}
	got, err := reloader.GetCertFromCache()
	if err != nil {
		t.Fatalf("GetCertFromCache() error = %v", err)
	}
	if got != cached {
		t.Error("failed refresh discarded the cached certificate")
	}
	if !reloader.mtime.Equal(mtime) {
		t.Error("failed refresh advanced the cached modification time")
	}
}
