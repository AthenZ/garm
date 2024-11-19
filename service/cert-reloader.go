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
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

var defaultPollInterval = 1 * time.Minute

// LogFn allows customized logging.
type LogFn func(format string, args ...interface{})

// CertReloader reloads the (key, cert) pair from the filesystem when
// the cert file is updated.
type CertReloader struct {
	l            sync.RWMutex
	certFile     string
	keyFile      string
	cert         *tls.Certificate
	certPEM      []byte
	keyPEM       []byte
	mtime        time.Time
	pollInterval time.Duration
	// logger       logger
	stop chan struct{}
}

// GetCertFromCache returns the latest known certificate.
func (w *CertReloader) GetCertFromCache() (*tls.Certificate, error) {
	w.l.RLock()
	c := w.cert
	w.l.RUnlock()
	return c, nil
}

// GetCertAndKeyFromCache returns the latest known key and certificate in raw bytes.
func (w *CertReloader) GetCertAndKeyFromCache() ([]byte, []byte, error) {
	w.l.RLock()
	k := w.keyPEM
	c := w.certPEM
	w.l.RUnlock()
	return k, c, nil
}

// type IdentityAthenzX509 = func() (*tls.Config, error)
func (w *CertReloader) GetWebhook() func() (*tls.Config, error) {
	return func() (*tls.Config, error) {
		cert, err := w.GetCertFromCache()
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return cert, nil
			},
		}, nil
	}
}

// Close stops CertReloader (or stops refreshing).
func (w *CertReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

// loadLocalCertAndKey loads cert & its key from local filesystem and update its own cache if the file has changed.
// Used to be called as "maybeReload"
func (w *CertReloader) loadLocalCertAndKey() error {
	st, err := os.Stat(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to stat %s", w.certFile))
	}
	if !st.ModTime().After(w.mtime) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s,%s", w.certFile, w.keyFile))
	}
	certPEM, err := os.ReadFile(w.certFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s", w.certFile))
	}
	keyPEM, err := os.ReadFile(w.keyFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load key from %s", w.keyFile))
	}
	w.l.Lock()
	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = st.ModTime()
	w.l.Unlock()

	glg.Info("certs reloaded from local file: key[%s], cert[%s] at %v", w.keyFile, w.certFile, time.Now()) // TODO: Check if it is "info"
	return nil
}

func (w *CertReloader) pollRefresh() error {
	poll := time.NewTicker(w.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.loadLocalCertAndKey(); err != nil {
				glg.Info("cert reload error from local file: key[%s], cert[%s]: %v", w.keyFile, w.certFile, err) // TODO: Check if it is "info"
			}
		case <-w.stop:
			return nil
		}
	}
}

// UpdateCertificate update certificate and key in cert reloader.
func (w *CertReloader) UpdateCertificate(certPEM []byte, keyPEM []byte) error {
	w.l.Lock()
	defer w.l.Unlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.Wrap(err, "unable to create tls.Certificate from provided PEM data")
	}

	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = time.Now()

	glg.Info("certs reloaded from provided PEM data at %v", time.Now()) // TODO: Check if it is "info"

	return nil
}

// CertReloaderCfg contains the config for cert reload.
type CertReloaderCfg struct {
	// if init mode: if it fails to read from cert/key files, it will return error.
	// if non-init mode: it will keep using the cache if it fails to read from cert/key files.
	// Init     bool
	CertPath     string        // the cert file path i.e) /var/run/athenz/tls.cert
	KeyPath      string        // the key file path i.e) /var/run/athenz/tls.key
	Logger       logger        // custom log function for errors, optional
	PollInterval time.Duration // TODO: Comment me
}

// NewCertReloader returns a CertReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func NewCertReloader(config CertReloaderCfg) (*CertReloader, error) {
	// if &config.Logger == nil {
	// 	return nil, errors.New("logger is required for CertReloader")
	// }

	if config.CertPath == "" || config.KeyPath == "" {
		return nil, fmt.Errorf("both cert [%s] and key file [%s] paths are required for CertReloader", config.CertPath, config.KeyPath)
	}

	if config.PollInterval == 0 {
		config.PollInterval = time.Duration(defaultPollInterval)
	}

	r := &CertReloader{
		certFile: config.CertPath,
		keyFile:  config.KeyPath,
		// logger:       config.Logger,
		pollInterval: config.PollInterval,
		stop:         make(chan struct{}, 10),
	}

	// load file once during the initialization:
	if err := r.loadLocalCertAndKey(); err != nil {
		// In init mode, return initialized CertReloader and error to confirm non-existence of files.
		return r, err
	}

	go r.pollRefresh() // make sure to read the files periodically
	return r, nil
}
