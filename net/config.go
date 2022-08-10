/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
)

type PartyConnectionConfig struct {
	AuthFunc func(tlsContext []byte) Handshake
	Domain   string
	Id       int
	Endpoint string
	TlsCAs   *x509.CertPool
}

type PartyEnvConfig struct {
	id       int
	endpoint string
	tlsCA    string
}

func (pec PartyEnvConfig) ToConnectionConfig() (PartyConnectionConfig, error) {
	z := PartyConnectionConfig{}
	// Check if endpoint is a valid host:port
	host, port, err := net.SplitHostPort(pec.endpoint)
	if err != nil {
		return z, fmt.Errorf("%s is not a valid host:port (%v)", pec.endpoint, err)
	}

	endpoint := net.JoinHostPort(host, port)

	tlsCADER, err := pec.extractTLSCAPEM()
	if err != nil {
		return z, err
	}

	tlsCA, err := x509.ParseCertificate(tlsCADER)
	if err != nil {
		return z, fmt.Errorf("%s encodes a PEM that is not a valid x509 certificate", pec.tlsCA)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCA)

	return PartyConnectionConfig{
		Endpoint: endpoint,
		TlsCAs:   certPool,
		Id:       pec.id,
	}, nil
}

func (pec PartyEnvConfig) extractTLSCAPEM() ([]byte, error) {
	// Check if TLS CA is a base64 encoded PEM
	maybeBase64Encoding, err := base64.StdEncoding.DecodeString(pec.tlsCA)
	if err == nil {
		// Check if it's a valid PEM
		bl, _ := pem.Decode(maybeBase64Encoding)
		if bl == nil {
			return nil, fmt.Errorf("%s is encoded in base64 but is not a valid PEM", pec.tlsCA)
		}
		return bl.Bytes, nil
	} else { // Check if it's a hex encoded PEM
		maybeHexEncoding, err := hex.DecodeString(pec.tlsCA)
		if err == nil {
			// Check if it's a valid PEM
			bl, _ := pem.Decode(maybeHexEncoding)
			if bl == nil {
				return nil, fmt.Errorf("%s is encoded in hex but is not a valid PEM", pec.tlsCA)
			}
			return bl.Bytes, nil
		} else { // Check if it's a valid PEM and not encoded in anything
			bl, _ := pem.Decode([]byte(pec.tlsCA))
			if bl == nil {
				return nil, fmt.Errorf("%s is not a PEM nor a base64 encoded PEM or a hex encoded PEM", pec.tlsCA)
			}
			return bl.Bytes, nil
		}
	}
}
