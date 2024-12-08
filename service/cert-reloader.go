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

// TODO: This code is based on athenz/k8s-athenz-sia's implementation:
// TODO: https://github.com/AthenZ/k8s-athenz-sia/blob/main/pkg/util/cert-reloader.go
// TODO: Yet, the original code is tailored specifically to k8s-athenz-sia's logic
// TODO: So we could not copy the k8s-athenz-sia's cert-reloader code as is.
// TODO: It would be beneficial to develop a more general-purpose library for this functionality in the future.
// TODO: This way, both Garm and k8s-athenz-sia could utilize the same library.
package service

import (
	"crypto/tls"
	"crypto/x509"
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
	certPath     string
	keyPath      string
	caPath       string
	cert         *tls.Certificate
	certPEM      []byte
	keyPEM       []byte
	caPool       *x509.CertPool // This is optional and can be nil
	mtime        time.Time
	pollInterval time.Duration
	stop         chan struct{}
}

// GetCertFromCache returns the latest known certificate.
func (w *CertReloader) GetCertFromCache() (*tls.Certificate, error) {
	w.l.RLock()
	c := w.cert
	w.l.RUnlock()
	return c, nil
}

// GetWebhook returns a function that is used to get X.509 Certificate stored in memory to connect to Athenz server
// type IdentityAthenzX509 = func() (*tls.Config, error)
func (w *CertReloader) GetWebhook() func() (*tls.Config, error) {
	return func() (*tls.Config, error) {
		cert, err := w.GetCertFromCache()

		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			RootCAs:      w.caPool,
		}, nil
	}
}

// Close stops CertReloader (or stops refreshing).
func (w *CertReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

// loadCAPool reads the CA cert from the local filesystem and save into memory as "caPool"
func (w *CertReloader) loadCAPool() error {
	// CA is optional
	if w.caPath == "" {
		return nil
	}

	caPEM, err := os.ReadFile(w.caPath)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load ca cert from %s", w.caPath))
	}

	caPool, err := NewX509CertPool(w.caPath)
	if err != nil {
		return errors.Wrap(err, "authorization x509 certpool error")
	}

	if !caPool.AppendCertsFromPEM(caPEM) {
		return errors.New("Certification Failed") // TODO: Something like "appending ca certificate into ca pool has failed"
	}

	// Finally:
	w.caPool = caPool
	return nil
}

// loadLocalCertAndKey loads cert & its key from local filesystem and update only if the file has changed or it is the first time.

func (w *CertReloader) loadLocalCertAndKey() error {
	// glg.Debugf("Attempting to load .athenz.cert[%s] .athenz.key[%s] from local file ...", w.certPath, w.keyPath)
	st, err := os.Stat(w.certPath)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to stat %s", w.certPath))
	}

	if !st.ModTime().After(w.mtime) {
		// glg.Debugf("Skipping to load .athenz.cert[%s] .athenz.key[%s] from local file as it has not changed ...", w.certPath, w.keyPath)
		return nil
	}
	cert, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s,%s", w.certPath, w.keyPath))
	}
	certPEM, err := os.ReadFile(w.certPath)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load cert from %s", w.certPath))
	}
	keyPEM, err := os.ReadFile(w.keyPath)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to load key from %s", w.keyPath))
	}

	w.l.Lock()
	w.cert = &cert
	w.certPEM = certPEM
	w.keyPEM = keyPEM
	w.mtime = st.ModTime()
	w.l.Unlock()

	glg.Infof("Successfully loaded .athenz.cert[%s] .athenz.key[%s] from local file", w.certPath, w.keyPath)
	return nil
}

func (w *CertReloader) pollRefresh() error {
	// glg.Debugf("Starting periodic poll refresh for .athenz.cert[%s] .athenz.key[%s] every[%s] ...", w.certPath, w.keyPath, w.pollInterval)
	poll := time.NewTicker(w.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.loadLocalCertAndKey(); err != nil {
				glg.Warnf("Failed to load .athenz.cert[%s] .athenz.key[%s] from local file: %v", w.certPath, w.keyPath, err)
			}
		case <-w.stop:
			return nil
		}
	}
}

// CertReloaderCfg contains the config for cert reload.
type CertReloaderCfg struct {
	CertPath string // path to the X.509 certificate file i.e) /var/run/athenz/tls.crt
	KeyPath  string // path to the X.509 certificate key i.e) /var/run/athenz/tls.key
	// path to the X.509 CA file i.e) /var/run/athenz/ca.crt
	// This is optional and can be empty
	// If empty, the reloader will not load the CA file.
	CaPath string
	// duration between consecutive reads of the certificate and key file i.e) 10s, 30m, 24h
	// This is not optional as the library is not aware how long the cert is valid for.
	PollInterval time.Duration
}

// NewCertReloader returns a CertReloader that reloads the (key, cert) pair whenever
// the cert file changes on the filesystem.
func NewCertReloader(config CertReloaderCfg) (*CertReloader, error) {
	glg.Infof("Booting X.509 certificate reloader with arg .athenz.cert[%s] .athenz.key[%s] .athenz.root_ca[%s] .athenz.poll_interval[%s]", config.CertPath, config.KeyPath, config.CaPath, config.PollInterval)

	if config.CertPath == "" || config.KeyPath == "" {
		return nil, fmt.Errorf("both cert [%s] and key file [%s] paths are required for CertReloader", config.CertPath, config.KeyPath)
	}

	if config.PollInterval == 0 {
		config.PollInterval = time.Duration(defaultPollInterval)
	}

	r := &CertReloader{
		certPath:     config.CertPath,
		keyPath:      config.KeyPath,
		caPath:       config.CaPath,
		pollInterval: config.PollInterval,
		stop:         make(chan struct{}, 10),
	}

	// Read CA only during the initialization:
	if err := r.loadCAPool(); err != nil {
		return nil, errors.Wrap(err, "failed to load CA pool")
	}

	// load file once during the initialization:
	if err := r.loadLocalCertAndKey(); err != nil {
		// In init mode, return initialized CertReloader and error to confirm non-existence of files.
		return r, err
	}

	go r.pollRefresh() // make sure to read the files periodically
	return r, nil
}
