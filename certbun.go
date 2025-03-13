package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
)

const endpoint = "https://api.porkbun.com/api/json/v3/ssl/retrieve"

type Config struct {
	apiKey       string
	secretApiKey string
	domain       string
	installDir   string
}

type SslReqBody struct {
	ApiKey       string `json:"apikey"`
	SecretApiKey string `json:"secretapikey"`
}

type SslResBody struct {
	Status     string `json:"status"`
	CertChain  string `json:"certificatechain"`
	PrivateKey string `json:"privatekey"`
	PublicKey  string `json:"publickey"`
}

func main() {
	if err := run(os.Stdout, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(_ io.Writer, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: certbot [path/to/config.env]")
	}

	err := godotenv.Load(args[1])
	if err != nil {
		return fmt.Errorf("failed to read config file: %s", err)
	}

	conf := parseConfig()
	client := &http.Client{Timeout: 10 * time.Second}

	ssl, err := getSsl(conf, client)
	if err != nil {
		return err
	}

	privPath := filepath.Join(conf.installDir, "private.key.pem")
	pubPath := filepath.Join(conf.installDir, "public.key.pem")
	certPath := filepath.Join(conf.installDir, "cert.pem")

	err = os.WriteFile(privPath, []byte(ssl.PrivateKey), 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key: %s", err)
	}

	err = os.WriteFile(pubPath, []byte(ssl.PublicKey), 0600)
	if err != nil {
		return fmt.Errorf("failed to write public key: %s", err)
	}

	err = os.WriteFile(certPath, []byte(ssl.CertChain), 0600)
	if err != nil {
		return fmt.Errorf("failed to write certificate: %s", err)
	}

	return nil
}

func parseConfig() *Config {
	conf := newConfig()

	conf.apiKey = os.Getenv("API_KEY")
	conf.secretApiKey = os.Getenv("SECRET_API_KEY")
	conf.domain = os.Getenv("DOMAIN")
	conf.installDir = os.Getenv("CERT_INSTALL_DIR")

	return conf
}

func newConfig() *Config {
	return &Config{}
}

func getSsl(conf *Config, client *http.Client) (*SslResBody, error) {
	body := SslReqBody{ApiKey: conf.apiKey, SecretApiKey: conf.secretApiKey}
	bodyJson, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %s", err)
	}

	uri := fmt.Sprintf("%s/%s", endpoint, conf.domain)
	res, err := client.Post(uri, "application/json", bytes.NewBuffer(bodyJson))
	if err != nil {
		return nil, fmt.Errorf("failed to request ssl certificates: %s", err)
	}

	resBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("response failed with status code: %d and body: %s", res.StatusCode, resBody)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read response payload: %s", err)
	}

	var sslResp SslResBody
	err = json.Unmarshal([]byte(resBody), &sslResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response payload: %s", err)
	}

	return &sslResp, nil
}
