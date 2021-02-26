// Package oauth2-client/clientcredentials provides a familiar HTTP client
// interface with automatic retries and exponential backoff. It is integrated
// with x/auth2/clientcredentials client library, which automatically obtains
// and refreshes oauth2 tokens with given client credentials.
// This library makes it very easy to drop into existing programs
// that calls service-apis protected with oauth2 client-credentials.
//
// Automatic retries if there are errors obtaining oauth2 token or calling
// http-apis, under certain conditions. Mainly, if an error is
// returned by the client (connection errors etc), or if a 500-range
// response is received, then a retry is invoked. Otherwise, the response is
// returned and left to the caller to interpret.
//
// This library is inspired by the Hashicorp's go-retryablehttp.
// https://github.com/hashicorp/go-retryablehttp

package clientcredentials

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	// Standard HTTP headers
	httpHeaderContentType = "Content-Type"
	httpHeaderRetryAfter  = "Retry-After"

	// Standard Content-Types
	contentTypeFormURLEncoded = "application/x-www-form-urlencoded"
)

var (
	// Default exponential backoff retry config: 1, 2, 4, 8 sec
	defaultRetryWaitMin = 1 * time.Second
	defaultRetryWaitMax = 30 * time.Second
	defaultRetryMax     = 4

	// A regular expression to match the error returned by net/http when the
	// configured number of redirects is exhausted. This error isn't typed
	// specifically so we resort to matching on the error string.
	redirectsErrorRe = regexp.MustCompile(`stopped after \d+ redirects\z`)

	// A regular expression to match the error returned by net/http when the
	// scheme specified in the URL is invalid. This error isn't typed
	// specifically so we resort to matching on the error string.
	schemeErrorRe = regexp.MustCompile(`unsupported protocol scheme`)

	// Default HTTP timeout
	defaultHTTPTimeout = 15 * time.Second

	// Default TLS config
	defaultTLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
)

// Config describes a 2-legged OAuth2 flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// TokenURL is the resource server's token endpoint URL.
	TokenURL string

	// HTTP request Timeout
	HTTPTimeout time.Duration

	// TLS Config. If not specified defaultTLSConfig is used.
	TLSConfig *tls.Config
}

// CheckRetry specifies a policy for handling retries. It is called
// following each request with the response and error values returned by
// the http.Client. If CheckRetry returns false, the Client stops retrying
// and returns the response to the caller. If CheckRetry returns an error,
// that error value is returned in lieu of the error from the request. The
// Client will close any response body when retrying, but if the retry is
// aborted it is up to the CheckRetry callback to properly close any
// response body before returning.
type CheckRetry func(ctx context.Context, resp *http.Response, err error) (bool, error)

// Backoff specifies a policy for how long to wait between retries.
// It is called after a failing request to determine the amount of time
// that should pass before trying again.
type Backoff func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration

// Client is used to make HTTP requests with oauth2 token. It adds additional functionality
// like automatic retries to tolerate minor outages.
type Client struct {
	HTTPClient *http.Client // Internal HTTP client.

	RetryWaitMin time.Duration // Minimum time to wait
	RetryWaitMax time.Duration // Maximum time to wait
	RetryMax     int           // Maximum number of retries

	// CheckRetry specifies the policy for handling retries, and is called
	// after each request. The default policy is DefaultRetryPolicy.
	CheckRetry CheckRetry

	// Backoff specifies the policy for how long to wait between retries
	Backoff Backoff
}

// NewClient creates a new Client with default settings.
func NewClient(cfg *Config) (*Client, error) {
	// Pass the transport with TLS settings to the oauth2 library in the context
	if cfg.TLSConfig == nil {
		cfg.TLSConfig = defaultTLSConfig
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = cfg.TLSConfig
	ctxClient := &http.Client{Transport: transport}
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, ctxClient)

	// Create the oauth2 Client
	config := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenURL,
	}
	httpClient := config.Client(ctx)
	if httpClient == nil {
		return nil, fmt.Errorf("Error creating Oauth2 http client for %s", config.TokenURL)
	}
	httpClient.Timeout = cfg.HTTPTimeout
	client := &Client{
		HTTPClient:   httpClient,
		RetryWaitMin: defaultRetryWaitMin,
		RetryWaitMax: defaultRetryWaitMax,
		RetryMax:     defaultRetryMax,
		CheckRetry:   DefaultRetryPolicy,
		Backoff:      DefaultBackoff,
	}
	log.Infof("oauth2/clientcredential client created: RetryWaitMin=%v, RetryWaitMax=%v, RetryMax=%d\n",
		client.RetryWaitMin, client.RetryWaitMax, client.RetryMax)

	return client, nil
}

// DefaultRetryPolicy provides a default callback for Client.CheckRetry, which
// will retry on connection errors and server errors.
func DefaultRetryPolicy(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err != nil {
		if v, ok := err.(*url.Error); ok {
			// Don't retry if the error was due to too many redirects.
			if redirectsErrorRe.MatchString(v.Error()) {
				return false, v
			}

			// Don't retry if the error was due to an invalid protocol scheme.
			if schemeErrorRe.MatchString(v.Error()) {
				return false, v
			}

			// Don't retry if the error was due to TLS cert verification failure.
			if _, ok := v.Err.(x509.UnknownAuthorityError); ok {
				return false, v
			}
		}

		// The error is likely recoverable so retry.
		return true, nil
	}

	// 429 Too Many Requests is recoverable.
	// 401 in case of token expiry is recoverable.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusUnauthorized {
		return true, nil
	}

	// Check the response code. We retry on 500-range responses to allow
	// the server time to recover, as 500's are typically not permanent
	// errors and may relate to outages on the server side. This will catch
	// invalid response codes as well, like 0 and 999.
	if resp.StatusCode == 0 || (resp.StatusCode >= http.StatusInternalServerError &&
		resp.StatusCode != http.StatusNotImplemented) {
		return true, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	return false, nil
}

// DefaultBackoff provides a default callback for Client.Backoff which
// will perform exponential backoff based on the attempt number and limited
// by the provided minimum and maximum durations.
//
// It also tries to parse Retry-After response header when a http.StatusTooManyRequests
// (HTTP Code 429) is found in the resp parameter. Hence it will return the number of
// seconds the server states it may be ready to process more requests from this client.
func DefaultBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if s, ok := resp.Header[httpHeaderRetryAfter]; ok {
				if sleep, err := strconv.ParseInt(s[0], 10, 64); err == nil {
					return time.Second * time.Duration(sleep)
				}
			}
		}
	}

	mult := math.Pow(2, float64(attemptNum)) * float64(min)
	sleep := time.Duration(mult)
	if float64(sleep) != mult || sleep > max {
		sleep = max
	}
	return sleep
}

// Do wraps calling an HTTP method with retries.
// This call blocks the caller go-routine until the api-call is successful,
// or fails after the maximum retries. The oauth2-token is obtained inline.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	log.Debugf("Performing request %s %s\n", req.Method, req.URL)

	var resp *http.Response
	var attempt int
	var shouldRetry bool
	var doErr, checkErr error

	for i := 0; ; i++ {
		attempt++

		var code int // HTTP response code

		// Attempt the request
		resp, doErr = c.HTTPClient.Do(req)
		if resp != nil {
			code = resp.StatusCode
		}

		// Check if we should continue with retries.
		shouldRetry, checkErr = c.CheckRetry(req.Context(), resp, doErr)
		if doErr != nil {
			log.Errorf("Request failed for %s %s, error => %v\n", req.Method, req.URL, doErr)
		}
		if !shouldRetry {
			break
		}

		// Check if tried the max number of times
		remain := c.RetryMax - i
		if remain <= 0 {
			break
		}

		// We're going to retry
		wait := c.Backoff(c.RetryWaitMin, c.RetryWaitMax, i, resp)
		desc := fmt.Sprintf("%s %s", req.Method, req.URL)
		if code > 0 {
			desc = fmt.Sprintf("%s (status: %d)", desc, code)
		}
		log.Debugf("Retrying request %s timeout=%d, remain=%d\n", desc, wait, remain)
		time.Sleep(wait)
	}

	// this is the closest we have to success criteria
	if doErr == nil && checkErr == nil && !shouldRetry {
		return resp, nil
	}

	err := doErr
	if checkErr != nil {
		err = checkErr
	}

	// CheckRetry thought the request was a failure, but didn't communicate why
	if err == nil {
		return nil, fmt.Errorf("%s %s giving up after %d attempt(s)",
			req.Method, req.URL, attempt)
	}

	return nil, fmt.Errorf("%s %s giving up after %d attempt(s): %w",
		req.Method, req.URL, attempt, err)
}

// Get is a convenience helper for doing simple GET requests.
// This call blocks the caller go-routine until the api-call is successful,
// or fails after the maximum retries. The oauth2-token is obtained inline.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Head is a convenience method for doing simple HEAD requests.
// This call blocks the caller go-routine until the api-call is successful,
// or fails after the maximum retries. The oauth2-token is obtained inline.
func (c *Client) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post is a convenience method for doing simple POST requests.
func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(httpHeaderContentType, contentType)
	return c.Do(req)
}

// PostForm is a convenience method for doing simple POST operations using
// pre-filled url.Values form data.
// This call blocks the caller go-routine until the api-call is successful,
// or fails after the maximum retries. The oauth2-token is obtained inline.
func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.Post(url, contentTypeFormURLEncoded, strings.NewReader(data.Encode()))
}
