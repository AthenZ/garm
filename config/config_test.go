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

package config

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	webhook "github.com/AthenZ/garm/v3/third_party/webhook"
)

func Test_requestInfo_Serialize(t *testing.T) {
	type fields struct {
		req RequestInfo
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Check serialize",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "dummyName",
				},
			},
			want: "dummyVerb,dummyNamespace,dummyAPIGroup,dummyResource,dummyName",
		},
		{
			name: "Check serialize with API group containing period",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummy.APIGroup",
					Resource:  "dummyResource",
					Name:      "dummyName",
				},
			},
			want: "dummyVerb,dummyNamespace,dummy.APIGroup,dummyResource,dummyName",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fields.req.Serialize()
			if got != tt.want {
				t.Errorf("Serialize() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func Test_requestInfo_Match(t *testing.T) {
	type args struct {
		req RequestInfo
	}
	type fields struct {
		req RequestInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Check match",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "dummyName",
				},
			},
			args: args{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "dummyName",
				},
			},
			want: true,
		},
		{
			name: "Check not match",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "dummyName",
				},
			},
			args: args{
				req: RequestInfo{
					Verb:      "notmatch",
					Namespace: "notmatch",
					APIGroup:  "notmatch",
					Resource:  "notmatch",
					Name:      "notmatch",
				},
			},
			want: false,
		},
		{
			name: "Check wildcard match",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "*",
				},
			},
			args: args{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "dummyNamespace",
					APIGroup:  "dummyAPIGroup",
					Resource:  "dummyResource",
					Name:      "any",
				},
			},
			want: true,
		},

		{
			name: "Check multiple wildcard match",
			fields: fields{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "*",
					APIGroup:  "dummyAPIGroup",
					Resource:  "*",
					Name:      "*",
				},
			},
			args: args{
				req: RequestInfo{
					Verb:      "dummyVerb",
					Namespace: "any",
					APIGroup:  "dummyAPIGroup",
					Resource:  "any",
					Name:      "any",
				},
			},
			want: true,
		},
		{
			name: "Check malicious resource name not match",
			fields: fields{
				req: RequestInfo{
					Verb:      "get",
					Namespace: "kube-system",
					APIGroup:  "garm",
					Resource:  "pods",
					Name:      "*",
				},
			},
			args: args{
				req: RequestInfo{
					Verb:      "create",
					Namespace: "kube-system",
					APIGroup:  "garm",
					Resource:  "pods",
					Name:      "get-kube-system-garm-pods-test",
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fields.req.Match(tt.args.req)
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
				return
			}
		})
	}
}

func TestNew(t *testing.T) {
	defaultDuration, _ := time.ParseDuration("0s")
	type args struct {
		path string
	}
	type test struct {
		name       string
		args       args
		beforeFunc func() error
		afterFunc  func() error
		want       *Config
		wantErr    error
	}
	tests := []test{
		{
			name: "Test file content not valid",
			args: args{
				path: "./testdata/invalid_config.yaml",
			},
			wantErr: fmt.Errorf("yaml parse failed: yaml: line 11: could not find expected ':'"),
		},
		{
			name: "Open file error",
			args: args{
				path: "./tmp",
			},
			beforeFunc: func() error {
				f, err := os.Create("./tmp")
				if err != nil {
					return err
				}
				defer f.Close()

				err = f.Chmod(0000)
				if err != nil {
					return err
				}

				return nil
			},
			afterFunc: func() error {
				return os.Remove("./tmp")
			},
			wantErr: fmt.Errorf("config read failed: open ./tmp: permission denied"),
		},
		{
			name: "Test file content valid",
			args: args{
				path: "./testdata/example_config.yaml",
			},
			want: &Config{
				Version: currentVersion,
				Logger: Logger{
					LogPath:  "/var/log/athenz/webhook.log",
					LogTrace: "server,athenz,mapping",
				},
				Server: Server{
					Port:             443,
					HealthzPort:      8080,
					HealthzPath:      "/healthz",
					Timeout:          "5s",
					ShutdownDuration: "5s",
					ProbeWaitTime:    "3s",
					TLS: TLS{
						Enabled: true,
						Cert:    "_cert_",
						Key:     "_key_",
						CA:      "_ca_",
					},
				},
				Athenz: Athenz{
					AuthHeader:   "Athenz-Principal-Auth",
					URL:          "https://www.athenz.com/zts/v1",
					Timeout:      "5s",
					AthenzRootCA: "_root_ca_",
					AuthN: webhook.AuthenticationConfig{
						Config: webhook.Config{
							ZMSEndpoint: "",
							ZTSEndpoint: "",
							AuthHeader:  "",
							Timeout:     defaultDuration,
							LogProvider: nil,
							LogFlags:    0,
							Validator:   nil,
						},
						Mapper: nil,
					},
					AuthZ: webhook.AuthorizationConfig{
						Config: webhook.Config{
							ZMSEndpoint: "",
							ZTSEndpoint: "",
							AuthHeader:  "",
							Timeout:     defaultDuration,
							LogProvider: nil,
							LogFlags:    0,
							Validator:   nil,
						},
						HelpMessage:               "",
						Token:                     nil,
						AthenzX509:                nil,
						AthenzClientAuthnx509Mode: false,
						Mapper:                    nil,
					},
					Config: webhook.Config{
						ZMSEndpoint: "",
						ZTSEndpoint: "",
						AuthHeader:  "",
						Timeout:     defaultDuration,
						LogProvider: nil,
						LogFlags:    0,
						Validator:   nil,
					},
				},
				Token: Token{
					AthenzDomain:    "_athenz_domain_",
					ServiceName:     "_athenz_service_",
					NTokenPath:      "/tmp/ntoken",
					PrivateKey:      "_athenz_private_key_",
					ValidateToken:   false,
					RefreshDuration: "10s",
					KeyVersion:      "v1.0",
					Expiration:      "5s",
				},
				Mapping: Mapping{
					TLD: TLD{
						Name: "aks",
						Platform: Platform{
							Name: "aks",
							ServiceAthenzDomains: []string{
								"_kaas_namespace_.k8s._k8s_cluster_1._namespace_",
								"_kaas_namespace_.k8s._k8s_cluster_2._namespace_"},
							ResourceMappings: map[string]string{
								"k8sResource1": "athenzResource1",
							},
							VerbMappings: map[string]string{
								"verb1": "action1",
							},
							APIGroupControlEnabled: true,
							APIGroupMappings: map[string]string{
								"": "core",
							},
							EmptyNamespace:             "all-namespace",
							ResourceNameControlEnabled: true,
							ResourceNameMappings: map[string]string{
								"resource": "resource",
							},
							NonResourceAPIGroup:  "nonres",
							NonResourceNamespace: "nonres",
							ServiceAccountPrefixes: []string{
								"system:serviceaccount:",
								"system-serviceaccount-",
							},
							AthenzUserPrefix:           "user.",
							AthenzServiceAccountPrefix: "_kaas_namespace_.k8s._k8s_cluster_2._namespace_.service_account.",
							AdminAthenzDomain:          "aks.admin",
							AdminAccessList:            nil,
							WhiteList:                  nil,
							BlackList:                  nil,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				err := tt.beforeFunc()
				if err != nil {
					t.Error(err)
				}
			}
			if tt.afterFunc != nil {
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Error(err)
					}
				}()
			}

			got, err := New(tt.args.path)

			if tt.wantErr == nil && err != nil {
				t.Errorf("New() unexpected error: %v", err)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v, got nil", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("New() error: %v, want: %v", err, tt.wantErr)
					return
				}
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New()= %v, want= %v", got, tt.want)
				return
			}
		})
	}
}

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Test get version return garm version",
			want: "v2.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetVersion(); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetActualValue(t *testing.T) {
	type args struct {
		val string
	}
	tests := []struct {
		name       string
		args       args
		beforeFunc func() error
		afterFunc  func() error
		want       string
	}{
		{
			name: "GetActualValue without env var",
			args: args{
				val: "test_env",
			},
			want: "test_env",
		},
		{
			name: "GetActualValue with env var",
			args: args{
				val: "_dummy_key_",
			},
			beforeFunc: func() error {
				return os.Setenv("dummy_key", "dummy_value")
			},
			afterFunc: func() error {
				return os.Unsetenv("dummy_key")
			},
			want: "dummy_value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				err := tt.beforeFunc()
				if err != nil {
					t.Error(err)
				}
			}
			if tt.afterFunc != nil {
				defer func() {
					err := tt.afterFunc()
					if err != nil {
						t.Error(err)
					}
				}()
			}

			if got := GetActualValue(tt.args.val); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPrefixAndSuffix(t *testing.T) {
	type args struct {
		str  string
		pref string
		suf  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Check true prefix and suffix",
			args: args{
				str:  "_dummy_",
				pref: "_",
				suf:  "_",
			},
			want: true,
		},
		{
			name: "Check false prefix and suffix",
			args: args{
				str:  "dummy",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
		{
			name: "Check true prefix but false suffix",
			args: args{
				str:  "_dummy",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
		{
			name: "Check false prefix but true suffix",
			args: args{
				str:  "dummy_",
				pref: "_",
				suf:  "_",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkPrefixAndSuffix(tt.args.str, tt.args.pref, tt.args.suf); got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
