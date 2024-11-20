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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AthenZ/garm/v3/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

var defaultPollInterval = 5 * time.Minute // sync once in a five minutes

// LogFn allows customized logging.
type LogFn func(format string, args ...interface{})

// CertReloader reloads the (key, cert) pair from the filesystem when
// the cert file is updated.
type CertReloader struct {
	l            sync.RWMutex
	token        config.Token
	certFile     string
	keyFile      string
	athenzRootCA string
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

// checkPrefixAndSuffix checks if the given string has given prefix and suffix.
func (w *CertReloader) checkPrefixAndSuffix(str, pref, suf string) bool {
	return strings.HasPrefix(str, pref) && strings.HasSuffix(str, suf)
}

// GetActualValue returns the environment variable value if the given val has "_" prefix and suffix, otherwise returns val directly.
func (w *CertReloader) GetActualValue(val string) string {
	if w.checkPrefixAndSuffix(val, "_", "_") {
		return os.Getenv(strings.TrimPrefix(strings.TrimSuffix(val, "_"), "_"))
	}
	return val
}

// type IdentityAthenzX509 = func() (*tls.Config, error)
func (w *CertReloader) GetWebhook() func() (*tls.Config, error) {
	return func() (*tls.Config, error) {
		cert, err := w.GetCertFromCache()
		// pool, err := NewX509CertPool(w.GetActualValue(w.athenzRootCA))

		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				glg.Info("GetCertificate called at %v", time.Now())
				return cert, nil
			},
			// RootCAs: pool,
		}, nil
	}
}

// Close stops CertReloader (or stops refreshing).
func (w *CertReloader) Close() error {
	w.stop <- struct{}{}
	return nil
}

// convertNTokenIntoX509 converts ntoken into x509 certificate and store into memory
func (w *CertReloader) convertNTokenIntoX509() error {
	return nil // TODO: For now
}

// pollRefresh periodically refreshes the cert and key based on given ntoken information
func (w *CertReloader) pollRefresh() error {
	poll := time.NewTicker(w.pollInterval)
	defer poll.Stop()
	for {
		select {
		case <-poll.C:
			if err := w.convertNTokenIntoX509(); err != nil {
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
	// CertPath     string // the cert file path i.e) /var/run/athenz/tls.cert
	// KeyPath      string // the key file path i.e) /var/run/athenz/tls.key
	Token config.Token
	// AthenzRootCa string // the root CA file path i.e) /var/run/athenz/root_ca.pem
	// Logger       logger        // custom log function for errors, optional
	// PollInterval time.Duration // TODO: Comment me
}

// NewCertConverter return CertRefresher that converts ntoken to x509 certificate
func NewCertConverter(config CertReloaderCfg) (*CertReloader, error) {
	// if &config.Logger == nil {
	// 	return nil, errors.New("logger is required for CertReloader")
	// }

	r := &CertReloader{
		token:        config.Token,
		pollInterval: defaultPollInterval,
	}

	// convert during the initalization:
	if err := r.convertNTokenIntoX509(); err != nil {
		// In init mode, return initialized CertReloader and error to confirm non-existence of files.
		return r, err
	}

	go r.pollRefresh() // make sure to read the files periodically
	return r, nil
}
