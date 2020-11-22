package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"4d63.com/tz"

	"github.com/DNSMadeEasy/dme-go-client/container"
	"github.com/DNSMadeEasy/dme-go-client/models"
)

const BaseURL = "https://api.dnsmadeeasy.com/V2.0/"

type Client struct {
	httpclient *http.Client
	apiKey     string //Required
	secretKey  string //Required
	insecure   bool   //Optional
	proxyurl   string //Optional

	requestLimit      int
	requestsRemaining int
}

const sleepMultiplier = 2.0
const minSleep = 3
const maxSleep = 300

//singleton implementation of a client
var clietnImpl *Client

type Option func(*Client)

func Insecure(insecure bool) Option {
	return func(client *Client) {
		client.insecure = insecure
	}
}

func ProxyUrl(pUrl string) Option {
	return func(client *Client) {
		client.proxyurl = pUrl
	}
}

func isRateLimitError(resp *http.Response) bool {
	lim, err := strconv.Atoi(resp.Header["X-Dnsme-Requestsreminaing"][0])

	if nil != err {
		return false
	}

	return lim <= 0
}

func (c *Client) updateRateLimits(resp *http.Response) {

	if limit, exists := resp.Header["X-Dnsme-Requestlimit"]; exists {
		lim, err := strconv.Atoi(limit[0])

		if err != nil {
			log.Printf("Updating DNSME Rate Limit, request limit: %d \n", lim)
			c.requestLimit = lim
		}
	}

	if limit, exists := resp.Header["X-Dnsme-Requestsreminaing"]; exists {
		lim, err := strconv.Atoi(limit[0])

		if err != nil {
			log.Printf("Updating DNSME Rate Limit, %d requests remaining\n", lim)
			c.requestsRemaining = lim
		}
	}
}

func (c *Client) rateLimitRequest(req *http.Request) (*http.Response, error) {
	if c.requestsRemaining == 0 || (float64(c.requestsRemaining)/float64(c.requestLimit)) < 0.2 {
		time.Sleep(minSleep * time.Second)
	}

	return c.doHTTPRequest(req, 0)
}

func (c *Client) retryRateLimitRequest(req *http.Request, retryCount int) (*http.Response, error) {
	sleepTime := time.Duration(minSleep * int64(math.Pow(sleepMultiplier, float64(retryCount))))
	sleepTime = time.Duration((math.Max(float64(sleepTime), float64(maxSleep))))
	log.Printf("Hit rate limit. Sleeping to back off, %s seconds (retry count %d)\n", sleepTime, retryCount)

	time.Sleep(sleepTime * time.Second)
	return c.doHTTPRequest(req, retryCount)
}

func (c *Client) doHTTPRequest(req *http.Request, retryCount int) (*http.Response, error) {
	resp, err := c.httpclient.Do(req)
	c.updateRateLimits(resp)

	if nil != err {
		fmt.Println("In HTTP err, Status code: ", resp.StatusCode)
		if isRateLimitError(resp) {
			return c.retryRateLimitRequest(req, retryCount+1)
		}

		return nil, err
	}

	return resp, nil
}

func initClient(apiKey, secretKey string, options ...Option) *Client {
	//existing information about client
	client := &Client{
		apiKey:    apiKey,
		secretKey: secretKey,
	}
	for _, option := range options {
		option(client)
	}

	//Setting up the HTTP client for the API call
	var transport *http.Transport
	transport = client.useInsecureHTTPClient(client.insecure)
	if client.proxyurl != "" {
		transport = client.configProxy(transport)
	}
	client.httpclient = &http.Client{
		Transport: transport,
	}
	return client
}

//Returns a singleton
func GetClient(apiKey, secretKey string, options ...Option) *Client {
	clietnImpl = initClient(apiKey, secretKey, options...)
	return clietnImpl
}

func (c *Client) useInsecureHTTPClient(insecure bool) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       insecure,
			MinVersion:               tls.VersionTLS11,
			MaxVersion:               tls.VersionTLS12,
		},
	}

	return transport
}

func (c *Client) configProxy(transport *http.Transport) *http.Transport {
	pUrl, err := url.Parse(c.proxyurl)
	if err != nil {
		log.Fatal(err)
	}
	transport.Proxy = http.ProxyURL(pUrl)
	return transport
}

func (c *Client) Save(obj models.Model, endpoint string) (*container.Container, error) {
	jsonPayload, err := c.PrepareModel(obj)
	if err != nil {
		return nil, err
	}
	log.Println("Payload is :", jsonPayload)

	url := fmt.Sprintf("%s%s", BaseURL, endpoint)
	req, err := c.makeRequest("POST", url, jsonPayload)
	if err != nil {
		return nil, err
	}
	log.Println("Request made : ", req)

	resp, err := c.rateLimitRequest(req)
	if err != nil {
		return nil, err
	}
	log.Println("Response is :", resp)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	respObj, err := container.ParseJSON(bodyBytes)
	if err != nil {
		return nil, err
	}

	respErr := checkForErrors(resp, respObj)
	if respErr != nil {
		return nil, respErr
	}
	return respObj, nil
}

func (c *Client) GetbyId(endpoint string) (*container.Container, error) {

	url := fmt.Sprintf("%s%s", BaseURL, endpoint)

	req, err := c.makeRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	log.Println("Request for get : ", req)

	resp, err1 := c.rateLimitRequest(req)
	if err1 != nil {
		return nil, err1
	}
	log.Println("response from get domain :", resp)

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	respObj, err := container.ParseJSON(bodyBytes)
	if err != nil {
		return nil, err
	}

	respErr := checkForErrors(resp, respObj)
	if respErr != nil {
		return nil, respErr
	}
	return respObj, nil
}

func (c *Client) Update(obj models.Model, endpoint string) (*container.Container, error) {
	jsonPayload, err := c.PrepareModel(obj)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s%s", BaseURL, endpoint)
	req, err := c.makeRequest("PUT", url, jsonPayload)
	log.Println(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.rateLimitRequest(req)
	if err != nil {
		return nil, err
	}
	log.Println(resp)

	if resp.StatusCode == 200 {
		return nil, nil
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	respObj, err := container.ParseJSON(bodyBytes)
	if err != nil {
		return nil, err
	}

	respErr := checkForErrors(resp, respObj)
	if respErr != nil {
		return nil, respErr
	}
	return respObj, nil
}

func (c *Client) Delete(endpoint string) error {
	url := fmt.Sprintf("%s%s", BaseURL, endpoint)

	req, err := c.makeRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	resp, err := c.rateLimitRequest(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 200 {
		return nil
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	respObj, err := container.ParseJSON(bodyBytes)
	if err != nil {
		return err
	}

	respErr := checkForErrors(resp, respObj)
	if respErr != nil {
		return respErr
	}
	return nil
}

func checkForErrors(resp *http.Response, obj *container.Container) error {
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		log.Println(" Into the check for errors ")
		if resp.StatusCode == 404 {
			return fmt.Errorf("Particular item not found")
		}

		errs := obj.S("error").Data().([]interface{})

		var allErrors string
		for _, tp := range errs {
			allErrors = allErrors + tp.(string)
		}
		return fmt.Errorf("%s", allErrors)
	}
	return nil
}

func (c *Client) PrepareModel(obj models.Model) (*container.Container, error) {
	con := obj.ToMap()

	payload := &container.Container{}

	for key, value := range con {
		payload.Set(value, key)
	}
	return payload, nil
}

func getToken(apikey, secretkey string) string {
	//epoch time in milliseconds
	loc, _ := tz.LoadLocation("GMT")
	now := time.Now().In(loc)
	time := now.Format("Mon, 2 Jan 2006 15:04:05 MST")

	//generates hmac from secret key
	h := hmac.New(sha1.New, []byte(secretkey))
	h.Write([]byte(time))
	sha := hex.EncodeToString(h.Sum(nil))

	return string(sha)
}

func (c *Client) makeRequest(method, endpoint string, con *container.Container) (*http.Request, error) {
	var req *http.Request
	var err error
	if method == "POST" || method == "PUT" {
		req, err = http.NewRequest(method, endpoint, bytes.NewBuffer(con.Bytes()))
	} else {
		req, err = http.NewRequest(method, endpoint, nil)
	}
	if err != nil {
		return nil, err
	}

	hmac := getToken(c.apiKey, c.secretKey)
	loc, _ := tz.LoadLocation("GMT")
	now := time.Now().In(loc)
	time := now.Format("Mon, 2 Jan 2006 15:04:05 MST")

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-dnsme-hmac", hmac)
	req.Header.Set("x-dnsme-apiKey", c.apiKey)
	req.Header.Set("x-dnsme-requestDate", time)

	return req, nil
}
