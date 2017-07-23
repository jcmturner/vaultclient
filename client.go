package vaultclient

import (
	"encoding/json"
	"errors"
	"fmt"
	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/jcmturner/restclient"
	"io/ioutil"
	"net/http"
)

// Client struct.
type Client struct {
	credentials *Credentials
	config      *Config
	session     *Session
}

type Credentials struct {
	AppID      string `json:"AppID"`
	UserID     string `json:"UserID"`
	UserIDFile string `json:"UserIDFile"`
}

type UserIdFile struct {
	UserID string `json:"UserID"`
}

type Config struct {
	apiConfig        *vaultAPI.Config
	apiClient        *vaultAPI.Client
	SecretsPath      string            `json:"SecretsPath"`
	ReSTClientConfig restclient.Config `json:"VaultConnection"`
}

type ErrSecretNotFound struct {}

func (e ErrSecretNotFound) Error() string {
	return "Secret not found in Vault"
}

func (creds *Credentials) ReadUserID() error {
	if creds.UserIDFile == "" {
		return errors.New("Could not read UserID as it is not defined")
	}
	j, err := ioutil.ReadFile(creds.UserIDFile)
	if err != nil {
		return fmt.Errorf("Could not open UserId file at %s: %v", creds.UserIDFile, err)
	}
	var uf UserIdFile
	err = json.Unmarshal(j, &uf)
	if err != nil {
		return fmt.Errorf("UserId file could not be parsed: %v", err)
	}
	creds.UserID = uf.UserID
	return nil
}

func NewClient(conf *Config, creds *Credentials) (Client, error) {
	if conf.apiConfig == nil {
		conf.apiConfig = vaultAPI.DefaultConfig()
		conf.apiConfig.Address = *conf.ReSTClientConfig.EndPoint
		conf.apiConfig.HttpClient = conf.ReSTClientConfig.HTTPClient
		// Create a new transport to void "protocol https already registered" panic
		conf.apiConfig.HttpClient.Transport = &http.Transport{
			TLSClientConfig: conf.apiConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig,
		}
	}
	if conf.apiClient == nil {
		c, err := vaultAPI.NewClient(conf.apiConfig)
		if err != nil {
			return Client{}, fmt.Errorf("Error creating Vault client: %v", err)
		}
		conf.apiClient = c
	}
	if creds.UserID == "" && creds.UserIDFile != "" {
		creds.ReadUserID()
	}
	var s Session
	err := s.NewRequest(&conf.ReSTClientConfig, creds.AppID, creds.UserID)
	if err != nil {
		return Client{}, fmt.Errorf("Error creating Vault login request object: %v", err)
	}
	token, err := s.GetToken()
	if err != nil {
		return Client{}, fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	conf.apiClient.SetToken(token)
	return Client{
		credentials: creds,
		config:      conf,
		session:     &s,
	}, nil
}

func (c *Client) List(p string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	// Refresh the access token to the vault if needs be
	token, err := c.session.GetToken()
	if err != nil {
		return m, fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.apiClient.SetToken(token)
	logical := c.config.apiClient.Logical()
	s, err := logical.List(c.config.SecretsPath + p)
	if err != nil {
		return nil, fmt.Errorf("Issue when reading secret from Vault at %s: %v", c.config.SecretsPath+p, err)
	}
	if s == nil {
		return nil, ErrSecretNotFound{}
	}
	return s.Data, err
}

func (c *Client) Read(p string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	// Refresh the access token to the vault if needs be
	token, err := c.session.GetToken()
	if err != nil {
		return m, fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.apiClient.SetToken(token)
	logical := c.config.apiClient.Logical()
	s, err := logical.Read(c.config.SecretsPath + p)
	if err != nil {
		return nil, fmt.Errorf("Issue when reading secret from Vault at %s: %v", c.config.SecretsPath+p, err)
	}
	if s == nil {
		return nil, ErrSecretNotFound{}
	}
	return s.Data, err
}

func (c *Client) Write(p string, m map[string]interface{}) error {
	// Refresh the access token to the vault if needs be
	token, err := c.session.GetToken()
	if err != nil {
		return fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.apiClient.SetToken(token)
	logical := c.config.apiClient.Logical()
	_, err = logical.Write(c.config.SecretsPath+p, m)
	return err
}

// Delete will delete the secret from Vault. The boolean indicates if the secret was found in the vault to be delete.
func (c *Client) Delete(p string) error {
	// Refresh the access token to the vault if needs be
	token, err := c.session.GetToken()
	if err != nil {
		return fmt.Errorf("Error getting login token to the Vault: %v", err)
	}
	c.config.apiClient.SetToken(token)
	logical := c.config.apiClient.Logical()
	_, err = logical.Delete(c.config.SecretsPath+p)
	if err != nil {
		return fmt.Errorf("Issue when deleting secret from Vault at %s: %v", c.config.SecretsPath+p, err)
	}
	return nil
}