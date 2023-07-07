// Package utils handles loading of signing key.
package utils

import (
	"crypto/rsa"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pkcs12"
)

// LoadSigningKey loads a RSA signing key out of a PKCS#12 container.
func LoadSigningKey(filePath, password string) (*rsa.PrivateKey, error) {
	// read the file content
	privateKeyData, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	return decodePrivateKey(privateKeyData, password)
}

// LoadSigningKeyFromReader loads a RSA signing key out of a PKCS#12 container from an io.Reader.
func LoadSigningKeyFromReader(r io.Reader, password string) (*rsa.PrivateKey, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return decodePrivateKey(b, password)
}

// The readFile fetches the content of a file located on the
// given path
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}

func decodePrivateKey(b []byte, password string) (*rsa.PrivateKey, error) {
	// decode file content to privateKey
	privateKey, _, err := pkcs12.Decode(b, password)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}
