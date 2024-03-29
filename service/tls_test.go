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
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/AthenZ/garm/v3/config"
)

func trim(str string) string {
	return strings.TrimRight(strings.TrimLeft(str, "_"), "_")
}

func TestNewTLSConfig(t *testing.T) {
	type args struct {
		CertPath string
		KeyPath  string
		CAPath   string
		cfg      config.TLS
	}
	defaultArgs := args{
		CertPath: "./testdata/dummyServer.crt",
		KeyPath:  "./testdata/dummyServer.key",
		CAPath:   "./testdata/dummyCa.pem",
		cfg: config.TLS{
			Cert: "_test1_Cert_",
			Key:  "_test1_Key_",
			CA:   "_test1_CA_",
		},
	}

	tests := []struct {
		name       string
		args       args
		want       *tls.Config
		beforeFunc func(args args)
		checkFunc  func(*tls.Config, *tls.Config) error
		afterFunc  func(args args)
		wantErr    error
	}{
		{
			name: "return value MinVersion test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), args.CAPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))

			},
			checkFunc: func(got, want *tls.Config) error {
				if got.MinVersion != want.MinVersion {
					return fmt.Errorf("MinVersion not Matched :\tgot %d\twant %d", got.MinVersion, want.MinVersion)
				}

				return nil
			},
		},
		{
			name: "return value CurvePreferences test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), args.CAPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))
			},
			checkFunc: func(got, want *tls.Config) error {
				if len(got.CurvePreferences) != len(want.CurvePreferences) {
					return fmt.Errorf("CurvePreferences not Matched length:\tgot %d\twant %d", len(got.CurvePreferences), len(want.CurvePreferences))
				}

				for _, actualValue := range got.CurvePreferences {
					var match bool

					for _, expectedValue := range want.CurvePreferences {
						if actualValue == expectedValue {
							match = true
							break
						}
					}

					if !match {
						return fmt.Errorf("CurvePreferences not Find :\twant %d", want.MinVersion)
					}
				}
				return nil
			},
		},
		{
			name: "return value SessionTicketsDisabled test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), args.CAPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.SessionTicketsDisabled != want.SessionTicketsDisabled {
					return fmt.Errorf("SessionTicketsDisabled not matched :\tgot %v\twant %v", got.SessionTicketsDisabled, want.SessionTicketsDisabled)
				}
				return nil
			},
		},
		{
			name: "return value Certificates test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), args.CAPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))
			},
			checkFunc: func(got, want *tls.Config) error {

				for _, wantVal := range want.Certificates {

					var notExist = false

					for _, gotVal := range got.Certificates {

						if gotVal.PrivateKey == wantVal.PrivateKey {

							notExist = true
							break
						}
					}
					if notExist {

						return fmt.Errorf("Certificates PrivateKey not Matched :\twant %s", wantVal.PrivateKey)
					}
				}
				return nil
			},
		},
		{
			name: "return value ClientAuth test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), args.CAPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))
			},
			checkFunc: func(got, want *tls.Config) error {

				if got.ClientAuth != want.ClientAuth {

					return fmt.Errorf("ClientAuth not Matched :\tgot %d \twant %d", got.ClientAuth, want.ClientAuth)
				}

				return nil
			},
		},
		{
			name: "cert file not found return value Certificates test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			checkFunc: func(got, want *tls.Config) error {
				if got.Certificates != nil {
					return fmt.Errorf("Certificates not nil")
				}

				return nil
			},
		},
		{
			name: "cert file not found return value ClientAuth test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates:           nil,
				ClientAuth:             tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), "notexists")
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
			},
			wantErr: fmt.Errorf("failed to load x509 key pair: open notexists: no such file or directory"),
		},
		{
			name: "CA file not found return value ClientAuth test.",
			args: defaultArgs,
			want: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.CurveP256,
					tls.X25519,
				},
				SessionTicketsDisabled: true,
				Certificates: func() []tls.Certificate {
					cert, _ := tls.LoadX509KeyPair(defaultArgs.CertPath, defaultArgs.KeyPath)
					return []tls.Certificate{cert}
				}(),
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
			beforeFunc: func(args args) {
				os.Setenv(trim(args.cfg.Cert), args.CertPath)
				os.Setenv(trim(args.cfg.Key), args.KeyPath)
				os.Setenv(trim(args.cfg.CA), "notexists")
			},
			afterFunc: func(args args) {
				os.Unsetenv(trim(args.cfg.Cert))
				os.Unsetenv(trim(args.cfg.Key))
				os.Unsetenv(trim(args.cfg.CA))
			},
			wantErr: fmt.Errorf("failed to load x509 ca: failed to read pem file: open notexists: no such file or directory"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got, err := NewTLSConfig(tt.args.cfg)

			if tt.wantErr == nil && err != nil {
				t.Errorf("NewTLSConfig() error: %v  wantErr: %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Error should occur: want error: %v  want: %v", err, tt.wantErr)
					return
				}
				// Here is comparing error message with expected
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Assertion failed: got: %v  want: %v", err, tt.wantErr)
					return
				}
			}

			if tt.checkFunc != nil {
				err = tt.checkFunc(got, tt.want)
				if err != nil {
					t.Errorf("NewTLSConfig() error = %v", err)
					return
				}
			}

			if tt.afterFunc != nil {
				tt.afterFunc(tt.args)
			}
		})
	}
}

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		path string
	}

	tests := []struct {
		name      string
		args      args
		want      *x509.CertPool
		checkFunc func(*x509.CertPool, *x509.CertPool) error
		wantErr   bool
	}{
		{
			name: "Check err if file not exist",
			args: args{
				path: "",
			},
			want: &x509.CertPool{},
			checkFunc: func(*x509.CertPool, *x509.CertPool) error {
				return nil
			},
			wantErr: true,
		},
		{
			name: "Check Append CA is correct",
			args: args{
				path: "./testdata/dummyCa.pem",
			},
			want: func() *x509.CertPool {
				wantPool := x509.NewCertPool()
				c, err := ioutil.ReadFile("./testdata/dummyCa.pem")
				if err != nil {
					panic(err)
				}
				if !wantPool.AppendCertsFromPEM(c) {
					panic(errors.New("Error appending certs from PEM"))
				}
				return wantPool
			}(),
			checkFunc: func(want *x509.CertPool, got *x509.CertPool) error {
				for _, wantCert := range want.Subjects() {
					exists := false
					for _, gotCert := range got.Subjects() {
						if strings.EqualFold(string(wantCert), string(gotCert)) {
							exists = true
						}
					}
					if !exists {
						return fmt.Errorf("Error\twant\t%s\t not found", string(wantCert))
					}
				}
				return nil
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewX509CertPool(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewX509CertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.checkFunc != nil {
				err = tt.checkFunc(tt.want, got)
				if err != nil {
					t.Errorf("TestNewX509CertPool error = %s", err)
				}
			}
		})
	}
}
