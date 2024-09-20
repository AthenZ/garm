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
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync/atomic"
	"time"

	"github.com/AthenZ/garm/v3/config"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// X509Service represents an interface for managing x509 certificates.
type X509Service interface {
	StartCertReloader(ctx context.Context) error // Starts the periodic certificate reloader
	GetTLSConfig() *tls.Config                   // Retrieves the current TLS configuration
}

type x509Service struct {
	cfg       config.X509Config
	tlsConfig atomic.Value // stores *tls.Config
}

// NewX509Service initializes a new x509Service with the provided configuration.
func NewX509Service(cfg config.X509Config) (X509Service, error) {
	s := &x509Service{
		cfg: cfg,
	}
	// Load the initial certificate
	err := s.reloadCert()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load initial x509 certificate")
	}
	return s, nil
}

// reloadCert loads the x509 certificate and updates the TLS configuration.
func (s *x509Service) reloadCert() error {
	// Load the certificate and key
	cert, err := tls.LoadX509KeyPair(s.cfg.Cert, s.cfg.Key)
	if err != nil {
		return errors.Wrap(err, "failed to load x509 key pair")
	}

	// Load the CA certificate if provided
	caCertPool := x509.NewCertPool()
	if s.cfg.CA != "" {
		caCert, err := os.ReadFile(s.cfg.CA)
		if err != nil {
			return errors.Wrap(err, "failed to read CA cert")
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	// Create the TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Set the RootCAs if certificate validation is enabled
	if s.cfg.ValidateCert {
		tlsConfig.RootCAs = caCertPool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	// Store the TLS configuration atomically
	s.tlsConfig.Store(tlsConfig)
	return nil
}

// StartCertReloader starts a goroutine to periodically reload the x509 certificate.
func (s *x509Service) StartCertReloader(ctx context.Context) error {
	ticker := time.NewTicker(1 * time.Hour) // Reload every hour
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				// Reload the certificate
				err := s.reloadCert()
				if err != nil {
					glg.Error(errors.Wrap(err, "failed to reload x509 certificate"))
				} else {
					glg.Info("Successfully reloaded x509 certificate")
				}
			}
		}
	}()
	return nil
}

// GetTLSConfig retrieves the current TLS configuration.
func (s *x509Service) GetTLSConfig() *tls.Config {
	return s.tlsConfig.Load().(*tls.Config)
}
