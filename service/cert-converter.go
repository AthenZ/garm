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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"

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
	athenz       config.Athenz
	token        config.Token
	ztsUrl       string
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

type signer struct {
	key       crypto.Signer
	algorithm x509.SignatureAlgorithm
}

func generateCSR(keySigner *signer, subj pkix.Name, host, instanceId, ip, uri string) (string, error) {
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: keySigner.algorithm,
	}
	if host != "" {
		template.DNSNames = []string{host}
	}
	if uri != "" {
		uriptr, err := url.Parse(uri)
		if err == nil {
			template.URIs = []*url.URL{uriptr}
		}
	}
	if instanceId != "" {
		uriptr, err := url.Parse(instanceId)
		if err == nil {
			if len(template.URIs) > 0 {
				template.URIs = append(template.URIs, uriptr)
			} else {
				template.URIs = []*url.URL{uriptr}
			}
		}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keySigner.key)
	if err != nil {
		return "", fmt.Errorf("cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func ntokenClient(ztsURL, ntoken, caCertFile, hdr string) (*zts.ZTSClient, error) {

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if caCertFile != "" {
		config := &tls.Config{}
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(caCert)
		config.RootCAs = certPool
		transport.TLSClientConfig = config
	}
	// use the ntoken to talk to Athenz
	client := zts.NewClient(ztsURL, transport)
	client.AddCredentials(hdr, ntoken)
	return &client, nil
}

// ExtractSignerInfo extract crypto.Signer and x509.SignatureAlgorithm from the given private key (ECDSA or RSA).
func ExtractSignerInfo(privateKeyPEM []byte) (crypto.Signer, x509.SignatureAlgorithm, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unable to load private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		return key, x509.ECDSAWithSHA256, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		return key, x509.SHA256WithRSA, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, x509.UnknownSignatureAlgorithm, err
		}
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return k, x509.ECDSAWithSHA256, nil
		case *rsa.PrivateKey:
			return k, x509.SHA256WithRSA, nil
		default:
			// PKCS#8 format may contain multiple key types other than RSA / EC, but current ZMS / ZTS server implementation only supports RSA / EC private keys
			return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported private key type: %s", reflect.TypeOf(k).Name())
		}
	default:
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func newSigner(privateKeyPEM []byte) (*signer, error) {
	key, algorithm, err := ExtractSignerInfo(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &signer{key: key, algorithm: algorithm}, nil
}

// convertNTokenIntoX509 converts ntoken into x509 certificate and store into memory
func (w *CertReloader) convertNTokenIntoX509() error {
	// TODO: Fixed for now
	domainName := "athenz.garm"
	serviceName := "service"
	hyphenDomain := strings.Replace(domainName, ".", "-", -1)
	dnsDomain := ".yahoo.co.jp" // This worked in svc-cert so its good
	fixedNTokenPath := "/etc/garm/ssl/athenz-private.key"

	ntokenBytes, err := os.ReadFile(fixedNTokenPath)
	if err != nil {
		return err
	} else {
		glg.Info("Successfully read ntoken from %s", fixedNTokenPath)
	}
	ntoken := strings.TrimSpace(string(ntokenBytes))
	if err != nil {
		log.Fatalln(err)
	} else {
		glg.Info("Successfully trim ntoken from %s", ntoken)
	}

	// get our private key signer for csr
	pkSigner, err := newSigner(ntokenBytes)
	if err != nil {
		log.Fatalln(err)
	} else {
		glg.Info("Successfully created private key signer from ntoken")
	}

	subj := pkix.Name{
		CommonName:         fmt.Sprintf("%s.%s", domainName, serviceName),
		OrganizationalUnit: []string{}, // empty for now
		Organization:       []string{}, // empty for now
		Country:            []string{}, // empty for now
	}
	host := fmt.Sprintf("%s.%s.%s", serviceName, hyphenDomain, dnsDomain)

	instanceId := "" // empty for now (it was empty for instance)
	ip := ""         // empty for now
	uri := ""        // empty for now
	csrData, err := generateCSR(pkSigner, subj, host, instanceId, ip, uri)
	if err != nil {
		log.Fatalln(err)
	} else {
		// Write down the CSR data as log:
		glg.Info("Successfully generated CSR data: %s", csrData)
	}

	expiryTime32 := int32(2400) // 2400s or 40 minutes (Fixed)
	req := &zts.InstanceRefreshRequest{
		Csr:        csrData,
		KeyId:      "e2e-test", // fixed for now
		ExpiryTime: &expiryTime32,
	}

	// hdr := "Yahoo-Principal-Auth" // TODO: fixed 2024/11/20 08:24:32 Post "https://alpha-apj.zts.athenz.yahoo.co.jp:4443/zts/v1/instance/athenz.garm/service/refresh": net/http: invalid head er field value for "Yahoo-Principal-Auth"
	caCertFile := "" // let's see if empty ca cert works
	client, err := ntokenClient(w.ztsUrl, ntoken, caCertFile, "")
	if err != nil {
		log.Fatalln(err)
	} else {
		glg.Info("Successfully created ntoken client")
	}

	// request a tls certificate for this service

	identity, err := client.PostInstanceRefreshRequest(zts.CompoundName(domainName), zts.SimpleName(serviceName), req)
	if err != nil {
		log.Fatalln(err)
	} else {
		glg.Info("Successfully posted instance refresh request")
	}

	w.UpdateCertificate([]byte(identity.Certificate), []byte(ntokenBytes)) // Save into cache (memory)
	return nil
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
	ZtsUrl string
	Token  config.Token
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
		ztsUrl:       config.ZtsUrl,
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
