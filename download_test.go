package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type subscriptionRequestTransportFunction func(*http.Request) (*http.Response, error)

func (requestTransportFunction subscriptionRequestTransportFunction) RoundTrip(subscriptionRequest *http.Request) (*http.Response, error) {
	return requestTransportFunction(subscriptionRequest)
}

type alwaysFailingSubscriptionResponseReader struct{}

func (alwaysFailingSubscriptionResponseReader) Read([]byte) (int, error) {
	return 0, errors.New("private-server response truncated")
}
func (alwaysFailingSubscriptionResponseReader) Close() error { return nil }

type repeatedSubscriptionResponseBodyReader struct{ remainingByteCount int }

func (responseBodyReader *repeatedSubscriptionResponseBodyReader) Read(destinationBuffer []byte) (int, error) {
	if responseBodyReader.remainingByteCount == 0 {
		return 0, io.EOF
	}
	if len(destinationBuffer) > responseBodyReader.remainingByteCount {
		destinationBuffer = destinationBuffer[:responseBodyReader.remainingByteCount]
	}
	for byteIndex := range destinationBuffer {
		destinationBuffer[byteIndex] = 'A'
	}
	responseBodyReader.remainingByteCount -= len(destinationBuffer)
	return len(destinationBuffer), nil
}

func TestSubscriptionDownloadsValidateResponseStatusAndBody(testContext *testing.T) {
	originalSubscriptionDownloadHttpClient := subscriptionDownloadHttpClient
	testContext.Cleanup(func() { subscriptionDownloadHttpClient = originalSubscriptionDownloadHttpClient })
	for _, testCase := range []struct {
		name      string
		status    int
		body      func() io.ReadCloser
		wantError bool
	}{
		{"success", 200, func() io.ReadCloser {
			return io.NopCloser(strings.NewReader("\ufeff trojan://synthetic@example.org:443\n"))
		}, false},
		{"http error", 403, func() io.ReadCloser { return io.NopCloser(strings.NewReader("private-token")) }, true},
		{"empty", 200, func() io.ReadCloser { return io.NopCloser(strings.NewReader(" \n")) }, true},
		{"truncated", 200, func() io.ReadCloser { return alwaysFailingSubscriptionResponseReader{} }, true},
		{"oversized", 200, func() io.ReadCloser {
			return io.NopCloser(&repeatedSubscriptionResponseBodyReader{maximumSubscriptionResponseBodySizeInBytes + 1})
		}, true},
	} {
		testContext.Run(testCase.name, func(testContext *testing.T) {
			subscriptionDownloadHttpClient = &http.Client{Transport: subscriptionRequestTransportFunction(func(subscriptionRequest *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: testCase.status, Body: testCase.body()}, nil
			})}
			content, operationError := downloadRawContentFromRemoteUrl("https://private-server/subscribe?token=private-token")
			if (operationError != nil) != testCase.wantError {
				testContext.Fatal("unexpected download result")
			}
			if operationError != nil && (strings.Contains(operationError.Error(), "private-server") || strings.Contains(operationError.Error(), "private-token")) {
				testContext.Fatal("download error leaked subscription")
			}
			if !testCase.wantError && content != "trojan://synthetic@example.org:443" {
				testContext.Fatal("body normalization failed")
			}
		})
	}
}

func TestSubscriptionDownloadsRespectTimeoutWithoutExposingPrivateUrls(testContext *testing.T) {
	originalSubscriptionDownloadHttpClient := subscriptionDownloadHttpClient
	testContext.Cleanup(func() { subscriptionDownloadHttpClient = originalSubscriptionDownloadHttpClient })
	subscriptionDownloadHttpClient = &http.Client{Timeout: 10 * time.Millisecond, Transport: subscriptionRequestTransportFunction(func(subscriptionRequest *http.Request) (*http.Response, error) {
		<-subscriptionRequest.Context().Done()
		return nil, subscriptionRequest.Context().Err()
	})}
	_, operationError := downloadRawContentFromRemoteUrl("https://private-server/subscribe?token=private-token")
	if operationError == nil || strings.Contains(operationError.Error(), "private-") {
		testContext.Fatal("timeout missing or leaked private URL")
	}
}
