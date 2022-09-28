// Package yzjapidecryption is yunzhijia api decryption
package yzjapidecryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	CloudFlowKey string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CloudFlowKey: "",
	}
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
		return nil, errors.New("cloudFlowKey cannot be empty")
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
	// 字符太少
	if len(body) < 16 {
		req.Header.Set("decryption", "false")
		req.Header.Set("errorMsg", "content to short")
		a.next.ServeHTTP(rw, req)
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
	req.Body = ioutil.NopCloser(strings.NewReader(jsonStr))
	req.ContentLength = int64(len(jsonStr))
	a.next.ServeHTTP(rw, req)
}

// DecodeBody decode body for key.
func DecodeBody(body, key string) (string, error) {
	descBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", err
	}
	jsonStr, err := aesDecrypt(descBytes, []byte(key))
	if err != nil {
		return "", err
	}
	return string(jsonStr), nil
}

// pKCS5UnPadding PKCS5.
func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// aesDecrypt ECB PKCS5.
func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pKCS5UnPadding(origData)
	return origData, nil
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}
func (x *ecbDecrypter) BlockSize() int { return x.blockSize }
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
