package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
)

const testRequestBodyLimit = 3 * 1024 * 1024

type bodyLimitUserMapper struct{}

func (bodyLimitUserMapper) MapUser(context.Context, string, string) (authn.UserInfo, error) {
	return authn.UserInfo{}, nil
}

type bodyLimitResourceMapper struct{}

func (bodyLimitResourceMapper) MapResource(_ context.Context, spec authz.SubjectAccessReviewSpec) (string, []AthenzAccessCheck, error) {
	return spec.User, nil, nil
}

type bodyLimitEndpoint struct {
	name       string
	path       string
	apiVersion string
	payload    string
	handler    http.Handler
}

func bodyLimitEndpoints() []bodyLimitEndpoint {
	cfg := Config{LogProvider: func(string) Logger { return log.New(io.Discard, "", 0) }}
	authorizer := NewAuthorizer(AuthorizationConfig{Config: cfg, Mapper: bodyLimitResourceMapper{}})
	return []bodyLimitEndpoint{
		{
			name:       "authn",
			path:       "/authn",
			apiVersion: "authentication.k8s.io/v1",
			payload:    `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"invalid-test-input"}}`,
			handler:    NewAuthenticator(AuthenticationConfig{Config: cfg, Mapper: bodyLimitUserMapper{}}),
		},
		{
			name:       "authz/v1",
			path:       "/authz",
			apiVersion: "authorization.k8s.io/v1",
			payload:    `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"example-user","resourceAttributes":{"verb":"get","resource":"pods"}}}`,
			handler:    authorizer,
		},
		{
			name:       "authz/v1beta1",
			path:       "/authz",
			apiVersion: "authorization.k8s.io/v1beta1",
			payload:    `{"apiVersion":"authorization.k8s.io/v1beta1","kind":"SubjectAccessReview","spec":{"user":"example-user","resourceAttributes":{"verb":"get","resource":"pods"}}}`,
			handler:    authorizer,
		},
	}
}

type whitespaceReader struct{}

func (whitespaceReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

type countedRequestBody struct {
	io.Reader
	bytesRead int64
}

func (b *countedRequestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytesRead += int64(n)
	return n, err
}

func (*countedRequestBody) Close() error { return nil }

func paddedRequestBody(payload string, size int64) *countedRequestBody {
	return &countedRequestBody{Reader: io.MultiReader(
		strings.NewReader(payload),
		io.LimitReader(whitespaceReader{}, size-int64(len(payload))),
	)}
}

func TestWebhookRequestBodyLimit(t *testing.T) {
	for _, endpoint := range bodyLimitEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, size := range []struct {
				name string
				n    int64
			}{
				{"small", int64(len(endpoint.payload))},
				{"below_limit", testRequestBodyLimit - 1},
				{"at_limit", testRequestBodyLimit},
				{"above_limit", testRequestBodyLimit + 1},
				{"larger_body", testRequestBodyLimit * 2},
			} {
				t.Run(size.name, func(t *testing.T) {
					for _, knownLength := range []bool{true, false} {
						name := "known_length"
						if !knownLength {
							name = "unknown_length"
						}
						t.Run(name, func(t *testing.T) {
							body := paddedRequestBody(endpoint.payload, size.n)
							req := httptest.NewRequest(http.MethodPost, endpoint.path, body)
							req.ContentLength = -1
							if knownLength {
								req.ContentLength = size.n
							}
							w := httptest.NewRecorder()
							endpoint.handler.ServeHTTP(w, req)

							wantStatus := http.StatusOK
							if size.n > testRequestBodyLimit {
								wantStatus = http.StatusRequestEntityTooLarge
							}
							if w.Code != wantStatus {
								t.Errorf("status = %d, want %d", w.Code, wantStatus)
							}
							if body.bytesRead > testRequestBodyLimit+1 {
								t.Errorf("read %d bytes, want at most %d", body.bytesRead, testRequestBodyLimit+1)
							}
							if wantStatus != http.StatusOK || w.Code != http.StatusOK {
								return
							}
							var response struct {
								APIVersion string
								Status     struct {
									Allowed       bool
									Authenticated bool
								}
							}
							if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
								t.Fatal(err)
							}
							if response.APIVersion != endpoint.apiVersion {
								t.Errorf("apiVersion = %q, want %q", response.APIVersion, endpoint.apiVersion)
							}
							if endpoint.path == "/authz" && !response.Status.Allowed {
								t.Error("expected the mapper's no-check authorization result")
							}
							if endpoint.path == "/authn" && response.Status.Authenticated {
								t.Error("invalid test input must not authenticate")
							}
						})
					}
				})
			}
		})
	}
}

type failedRequestBody struct{}

func (failedRequestBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestWebhookRequestBodyValidation(t *testing.T) {
	for _, endpoint := range bodyLimitEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, input := range []struct {
				name string
				body io.Reader
			}{
				{"empty", strings.NewReader("")},
				{"malformed", strings.NewReader("{")},
				{"read_error", failedRequestBody{}},
			} {
				t.Run(input.name, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPost, endpoint.path, input.body)
					w := httptest.NewRecorder()
					endpoint.handler.ServeHTTP(w, req)
					if w.Code != http.StatusBadRequest {
						t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
					}
				})
			}
		})
	}
}

func TestWebhookChunkedRequestBodyLimit(t *testing.T) {
	for _, endpoint := range bodyLimitEndpoints() {
		t.Run(endpoint.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" {
					t.Errorf("expected a chunked request, got length %d and encoding %v", r.ContentLength, r.TransferEncoding)
				}
				endpoint.handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 5 * time.Second
			for _, test := range []struct {
				name       string
				size       int64
				wantStatus int
			}{
				{"at_limit", testRequestBodyLimit, http.StatusOK},
				{"above_limit", testRequestBodyLimit + 1, http.StatusRequestEntityTooLarge},
			} {
				t.Run(test.name, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+endpoint.path,
						paddedRequestBody(endpoint.payload, test.size))
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != test.wantStatus {
						t.Errorf("status = %d, want %d", resp.StatusCode, test.wantStatus)
					}
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
