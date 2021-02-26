# oauth2-client
Resilient Oauth2 Clients with Retry and Backoff, written in golang.

## go-oauth2-client/clientcredentials

The go-oauth2-client/clientcredentials package provides a familiar HTTP client interface with automatic retries and exponential backoff. It is integrated with the standard x/oauth2/clientcredentials client library, which automatically obtains and refreshes oauth2 tokens with given client credentials. This library makes it very easy to drop into existing programs that calls service-apis protected with oauth2 client-credentials.

### Example Use
First get a client object with the oauth2 client-credentials.

```go
import oauth2cc "https://github.com/manaspanda/go-oauth2-client/clientcredentials"

//ClientID: The client ID of the OAuth2 client credentials
//ClientSecret: The client secret of the OAuth2 client credentials
//TokenURL: The token endpoint of the OAuth2 server
config := &oauth2cc.Config{
    ClientID:     clientId,
    ClientSecret: clientSecret,
    TokenURL:     proxyURI + tokenPath,
}
client, err := oauth2cc.NewClient(config)
if err != nil {
    panic(err)
}
```

Optionally, tune the retry parameters. The default is [RetryWaitMin=1 sec, RetryWaitMax=30 sec, RetryMax = 4], resulting in exponential backoff retry after 1, 2, 4, 8 sec, before failing.

```go
client.RetryWaitMin = 2 * time.Second  // Minimum time to wait
client.RetryWaitMax = 60 * time.Second // Maximum time to wait
client.RetryMax = 3                    // Maximum number of retries
```

Use the client object to make http(s) calls to a service, protected with oauth2 tokens, as you would do with `net/http`. The most simple example of a GET request is shown below:

```go
resp, err := client.Get("https://awesomeservice/v1/foo")
if err != nil {
    panic(err)
}
```

The returned response object is an `*http.Response`, the same thing you would usually get from `net/http`. Had the request failed one or more times, the above call would block and retry with exponential backoff.
