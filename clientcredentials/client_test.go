package clientcredentials

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	testTokenEp = "/oauth2/token"
	testApiEp   = "/api/foo"

	testClientID     = "CLIENT_ID"
	testClientSecret = "CLIENT_SECRET"

	testTokenFormRsp = "access_token=TOKEN&token_type=bearer&expires_in=300"
	testTokenJsonRsp = `{"token_type": "bearer", "access_token": "TOKEN", "expires_in": 300}`
	testApiRsp       = "foo-response"

	testBadApiURLEscape   = "https://[fe80::%31]:8080/api/foo"
	testBadApiURLProtocol = "badproto://localhost/api/foo"
)

var (
	testTokenFailCount  = 0
	testApiFailCount    = 0
	testRetryAfterInSec = 0

	testServer *httptest.Server
)

// ------------------------ Helper Functions -----------------------

// Create a test server with token end-point and test-api
func newTestServer() *httptest.Server {

	mux := http.NewServeMux()

	// Test Token endpoint
	mux.HandleFunc(testTokenEp, func(res http.ResponseWriter, req *http.Request) {
		if testTokenFailCount != 0 {
			res.WriteHeader(http.StatusUnauthorized)
			testTokenFailCount--
		} else {
			res.Header().Set(httpHeaderContentType, contentTypeFormURLEncoded)
			res.Write([]byte(testTokenFormRsp))
		}
	})

	// Test API end-point
	mux.HandleFunc(testApiEp, func(res http.ResponseWriter, req *http.Request) {
		if testApiFailCount != 0 {
			res.WriteHeader(http.StatusInternalServerError)
			testApiFailCount--
		} else if testRetryAfterInSec != 0 {
			res.Header().Add(httpHeaderRetryAfter, fmt.Sprintf("%d", testRetryAfterInSec))
			res.WriteHeader(http.StatusTooManyRequests)
			testRetryAfterInSec = 0
		} else {
			res.Write([]byte(testApiRsp))
		}
	})

	return httptest.NewTLSServer(mux)
}

// Get oauth2 Client object
func newOauth2Client(t *testing.T) *Client {
	t.Helper()

	// Client config
	config := &Config{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		TokenURL:     testServer.URL + testTokenEp,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	}
	// Create the client. Use short retry windows so we fail faster.
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	client.RetryWaitMin = 10 * time.Millisecond
	client.RetryWaitMax = 10 * time.Millisecond
	client.RetryMax = 2
	return client
}

// ------------------------ Unit tests -----------------------

func TestMain(m *testing.M) {
	// Set log-level when debugging the testcode
	// log.SetLevel(log.DebugLevel)
	log.SetOutput(ioutil.Discard)

	// Create the test server
	testServer = newTestServer()

	// Run tests
	exitVal := m.Run()

	// Close test-server and exit
	testServer.Close()
	os.Exit(exitVal)
}

func TestClientDo(t *testing.T) {

	tests := []struct {
		name           string
		tokenFailCount int
		apiFailCount   int
		expectedCode   int
		expectedErr    string
	}{
		{"SuccessNoRetry", 0, 0, http.StatusOK, ""},
		{"SuccessWithTokenRetry", 2, 0, http.StatusOK, ""},
		{"SuccessWithApiRetry", 2, 0, http.StatusOK, ""},
		{"FailureAfterMaxTokenRetry", 5, 0, http.StatusUnauthorized, "giving up after 3 attempt(s)"},
		{"FailureAfterMaxApiRetry", 0, 5, http.StatusInternalServerError, "giving up after 3 attempt(s)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newOauth2Client(t)

			// Create the request
			req, err := http.NewRequest(http.MethodGet, testServer.URL+testApiEp, nil)
			if err != nil {
				t.Fatalf("Failed to create a request, err: %v", err)
			}

			// Send the request.
			testTokenFailCount = tt.tokenFailCount
			testApiFailCount = tt.apiFailCount
			rsp, err := client.Do(req)
			if rsp != nil && rsp.StatusCode != tt.expectedCode {
				t.Fatalf("Expected statuscode %#v, got: %#v", tt.expectedCode, rsp.StatusCode)
			}
			if tt.expectedErr == "" && err != nil {
				t.Fatalf("Bad URL, expected to fail, but did not, err =%#v", err)
			}
			if err != nil && !strings.Contains(err.Error(), tt.expectedErr) {
				t.Fatalf("Expected giving up error, got: %#v", err)
			}
		})
	}

}

func TestClientGet(t *testing.T) {

	t.Run("SuccessNoRetry", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Get api on the client
		testTokenFailCount, testApiFailCount = 0, 0
		rsp, err := client.Get(testBadApiURLEscape)
		if err == nil {
			t.Fatalf("Bad URL, expected to fail, but did not")
		}
		rsp, err = client.Get(testServer.URL + testApiEp)
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status code, got: %#v", rsp.StatusCode)
		}
		if err != nil {
			t.Fatalf("Unexpected error, got: %#v", err)
		}
	})

	t.Run("SuccessRetryAfterHeader", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Get api on the client
		testTokenFailCount, testApiFailCount, testRetryAfterInSec = 0, 0, 1
		rsp, err := client.Get(testServer.URL + testApiEp)
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status code, got: %#v", rsp.StatusCode)
		}
		if err != nil {
			t.Fatalf("Unexpected error, got: %#v", err)
		}
	})

	t.Run("FailureProtoErrorNoRetry", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Get api on the client with a bad-proto-url
		testTokenFailCount, testApiFailCount, testRetryAfterInSec = 0, 0, 0
		_, err := client.Get(testBadApiURLProtocol)
		if err != nil && !schemeErrorRe.MatchString(err.Error()) {
			t.Fatalf("Expected protocol error, got: %#v", err)
		}
	})
}

func TestClientHead(t *testing.T) {

	t.Run("SuccessNoRetry", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Head api on the client
		testTokenFailCount, testApiFailCount = 0, 0
		rsp, err := client.Head(testBadApiURLEscape)
		if err == nil {
			t.Fatalf("Bad URL, expected to fail, but did not")
		}
		rsp, err = client.Head(testServer.URL + testApiEp)
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status code, got: %#v", rsp.StatusCode)
		}
		if err != nil {
			t.Fatalf("Unexpected error, got: %#v", err)
		}
	})
}

func TestClientPost(t *testing.T) {

	t.Run("SuccessNoRetry", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Post api on the client
		testTokenFailCount, testApiFailCount = 0, 0
		rsp, err := client.Post(testBadApiURLEscape, contentTypeFormURLEncoded, nil)
		if err == nil {
			t.Fatalf("Bad URL, expected to fail, but did not")
		}
		rsp, err = client.Post(testServer.URL+testApiEp, contentTypeFormURLEncoded, nil)
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status code, got: %#v", rsp.StatusCode)
		}
		if err != nil {
			t.Fatalf("Unexpected error, got: %#v", err)
		}
	})
}

func TestClientPostForm(t *testing.T) {

	t.Run("SuccessNoRetry", func(t *testing.T) {
		client := newOauth2Client(t)

		// Call Post api on the client
		testTokenFailCount, testApiFailCount = 0, 0
		kv := url.Values{"key": {"Value"}, "id": {"123"}}
		rsp, err := client.PostForm(testServer.URL+testApiEp, kv)
		if rsp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status code, got: %#v", rsp.StatusCode)
		}
		if err != nil {
			t.Fatalf("Unexpected error, got: %#v", err)
		}
	})
}
