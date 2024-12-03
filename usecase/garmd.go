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

package usecase

import (
	"context"
	"time"

	"github.com/AthenZ/garm/v3/config"
	"github.com/AthenZ/garm/v3/handler"
	"github.com/AthenZ/garm/v3/router"
	"github.com/AthenZ/garm/v3/service"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// GarmDaemon represents Garm daemon behavior.
type GarmDaemon interface {
	Start(ctx context.Context) chan []error
}

type garm struct {
	UseX509Mode  bool // true: use x509 mode, false: use token mode
	cfg          config.Config
	certReloader *service.CertReloader
	token        service.TokenService
	athenz       service.Athenz
	server       service.Server
}

// New returns a Garm daemon, or error occurred.
// The daemon contains a token service authentication and authorization server.
// This function will also initialize the mapping rules for the authentication and authorization check.
func New(cfg config.Config) (GarmDaemon, error) {
	logger := service.NewLogger(cfg.Logger)
	useX509Mode := cfg.X509.Cert != "" && cfg.X509.Key != ""
	// Log out here:
	glg.Info("Garm is starting with X.509 mode=", useX509Mode)

	var token service.TokenService
	var certReloader *service.CertReloader
	var athenz service.Athenz
	var err error

	if useX509Mode {
		certReloader, err = service.NewCertReloader(service.CertReloaderCfg{
			CertPath:     cfg.X509.Cert,
			KeyPath:      cfg.X509.Key,
			PollInterval: time.Second, // TODO: Is this correct that we fix the poll interval?
			AthenzRootCa: cfg.Athenz.AthenzRootCA,
		})
		if err != nil {
			return nil, errors.Wrap(err, "cert reloader instantiate failed")
		}

		// Create Athenz object for X.509:
		athenz, err = service.NewX509Athenz(cfg.Athenz, certReloader.GetWebhook(), logger)
		if err != nil {
			return nil, errors.Wrap(err, "athenz service instantiate failed")
		}
	} else {
		token, err = service.NewTokenService(cfg.Token)
		if err != nil {
			return nil, errors.Wrap(err, "token service instantiate failed")
		}

		// set token source (function pointer):
		cfg.Athenz.AuthZ.Token = token.GetToken

		// Create Athenz object:
		athenz, err = service.NewAthenz(cfg.Athenz, logger)
		if err != nil {
			return nil, errors.Wrap(err, "athenz service instantiate failed")
		}
	}

	resolver := service.NewResolver(cfg.Mapping)
	// set up mapper
	cfg.Athenz.AuthZ.Mapper = service.NewResourceMapper(resolver)
	cfg.Athenz.AuthN.Mapper = service.NewUserMapper(resolver)

	return &garm{
		UseX509Mode: useX509Mode,
		cfg:         cfg,
		token:       token,
		athenz:      athenz,
		server:      service.NewServer(cfg.Server, router.New(cfg.Server, handler.New(athenz))),
	}, nil
}

// Start returns an error slice channel. This error channel reports the errors inside Garm server.
func (g *garm) Start(ctx context.Context) chan []error {
	if g.UseX509Mode {
		// ... TODO: Do something
	} else {
		g.token.StartTokenUpdater(ctx)
	}
	return g.server.ListenAndServe(ctx)
}
