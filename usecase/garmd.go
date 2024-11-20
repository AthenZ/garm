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

	"github.com/AthenZ/garm/v3/config"
	"github.com/AthenZ/garm/v3/handler"
	"github.com/AthenZ/garm/v3/router"
	"github.com/AthenZ/garm/v3/service"
	"github.com/pkg/errors"
)

// GarmDaemon represents Garm daemon behavior.
type GarmDaemon interface {
	Start(ctx context.Context) chan []error
}

type garm struct {
	cfg          config.Config
	token        service.TokenService
	athenz       service.Athenz
	server       service.Server
	certReloader *service.CertReloader
}

// New returns a Garm daemon, or error occurred.
// The daemon contains a token service authentication and authorization server.
// This function will also initialize the mapping rules for the authentication and authorization check.
func New(cfg config.Config) (GarmDaemon, error) {
	// TODO: Create a logic later:
	// token, err := service.NewTokenService(cfg.Token)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "token service instantiate failed")
	// }
	logger := service.NewLogger(cfg.Logger)

	// TODO: use certConverter to reload cert
	certConverter, err := service.NewCertConverter(service.CertReloaderCfg{
		Token:  cfg.Token,
		ZtsUrl: cfg.Athenz.URL,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cert reloader instantiate failed")
	}

	resolver := service.NewResolver(cfg.Mapping)
	// set up mapper
	cfg.Athenz.AuthZ.Mapper = service.NewResourceMapper(resolver)
	cfg.Athenz.AuthN.Mapper = service.NewUserMapper(resolver)

	// set token source (function pointer)
	// cfg.Athenz.AuthZ.Token = token.GetToken
	// cfg.Athenz.AuthZ.AthenzClientAuthnx509Mode = true
	// cfg.Athenz.AuthZ.AthenzX509 = certReloader.GetWebhook()

	athenz, err := service.NewX509Athenz(cfg.Athenz, certConverter.GetWebhook(), logger)
	if err != nil {
		return nil, errors.Wrap(err, "athenz service instantiate failed")
	}

	return &garm{
		cfg: cfg,
		// token:        token,
		athenz:       athenz,
		server:       service.NewServer(cfg.Server, router.New(cfg.Server, handler.New(athenz))),
		certReloader: certConverter,
	}, nil
}

// Start returns an error slice channel. This error channel reports the errors inside Garm server.
func (g *garm) Start(ctx context.Context) chan []error {
	// g.token.StartTokenUpdater(ctx)
	return g.server.ListenAndServe(ctx)
}
