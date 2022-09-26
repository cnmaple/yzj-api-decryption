package yzj_api_decryption

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cnmaple/yzj_api_decryption/aes"
	"io/ioutil"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	CloudFlowKey string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// YzjDecryptionPlugin yzj decryption plugin.
type YzjDecryptionPlugin struct {
	next         http.Handler
	cloudFlowKey string
	name         string
}

// New created a yzj decryption plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.CloudFlowKey) == 0 {
		return nil, fmt.Errorf("cloudFlowKey cannot be empty")
	}
	return &YzjDecryptionPlugin{
		cloudFlowKey: config.CloudFlowKey,
		next:         next,
		name:         name,
	}, nil
}

func (a *YzjDecryptionPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		req.Header.Set("decryption", "false")
		req.Header.Set("errorMsg", err.Error())
		a.next.ServeHTTP(rw, req)
		return
	}

	jsonStr, err := DecodeBody(string(body), a.cloudFlowKey)
	if err != nil {
		req.Header.Set("decryption", "false")
		req.Header.Set("errorMsg", err.Error())
		a.next.ServeHTTP(rw, req)
		return
	}
	var results map[string]interface{}
	err = json.Unmarshal([]byte(jsonStr), &results)
	if err != nil {
		req.Header.Set("decryption", "false")
		req.Header.Set("errorMsg", "cloudFlowKey is error, err Message:"+err.Error())
		a.next.ServeHTTP(rw, req)
		return
	}
	req.Header.Set("decryption", "true")
	req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(jsonStr)))
	a.next.ServeHTTP(rw, req)
}

func DecodeBody(body string, key string) (string, error) {
	descBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", err
	}
	jsonStr, err := aes.AesDecrypt(descBytes, []byte(key))
	if err != nil {
		fmt.Println(err.Error())
		return "", err
	}
	return string(jsonStr), nil
}
