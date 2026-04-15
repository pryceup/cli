// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/larksuite/cli/internal/core"
)

// RunAuthCodeFlow executes the full authorization code flow:
// 1. Start local HTTP server for callback
// 2. Open browser to authorize URL
// 3. Wait for callback with authorization code
// 4. Exchange code for tokens
func RunAuthCodeFlow(ctx context.Context, httpClient *http.Client,
	appId, appSecret string, ep core.Endpoints, scope string,
	port int, errOut io.Writer) (*DeviceFlowResult, error) {

	if errOut == nil {
		errOut = io.Discard
	}

	state, err := randomState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	// Channel to receive the authorization code
	codeCh := make(chan callbackResult, 1)

	// Start local HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			codeCh <- callbackResult{err: fmt.Errorf("state mismatch")}
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}
		if errMsg := q.Get("error"); errMsg != "" {
			codeCh <- callbackResult{err: fmt.Errorf("%s: %s", errMsg, q.Get("error_description"))}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, authFailHTML, errMsg)
			return
		}
		code := q.Get("code")
		if code == "" {
			codeCh <- callbackResult{err: fmt.Errorf("no authorization code in callback")}
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}
		codeCh <- callbackResult{code: code}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, authSuccessHTML)
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server on port %d: %w", port, err)
	}
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	// Build authorize URL
	authorizeURL := buildAuthorizeURL(ep.Open, appId, redirectURI, state, scope)

	fmt.Fprintf(errOut, "[lark-cli] Opening browser for authorization...\n")
	fmt.Fprintf(errOut, "  %s\n\n", authorizeURL)

	if err := openBrowser(authorizeURL); err != nil {
		fmt.Fprintf(errOut, "[lark-cli] Could not open browser automatically. Please open the URL above manually.\n")
	}

	// Wait for callback or context cancellation
	fmt.Fprintf(errOut, "[lark-cli] Waiting for authorization callback on localhost:%d...\n", port)
	select {
	case result := <-codeCh:
		if result.err != nil {
			return &DeviceFlowResult{OK: false, Error: "access_denied", Message: result.err.Error()}, nil
		}
		// Exchange code for token
		return exchangeCodeForToken(httpClient, ep, appId, appSecret, result.code, redirectURI, errOut)
	case <-ctx.Done():
		return &DeviceFlowResult{OK: false, Error: "expired_token", Message: "Authorization was cancelled"}, nil
	case <-time.After(5 * time.Minute):
		return &DeviceFlowResult{OK: false, Error: "expired_token", Message: "Authorization timed out (5 minutes)"}, nil
	}
}

type callbackResult struct {
	code string
	err  error
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func buildAuthorizeURL(openBase, appId, redirectURI, state, scope string) string {
	v := url.Values{}
	v.Set("client_id", appId)
	v.Set("redirect_uri", redirectURI)
	v.Set("response_type", "code")
	v.Set("state", state)
	if scope != "" {
		v.Set("scope", scope)
	}
	return openBase + PathAuthorize + "?" + v.Encode()
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}

func exchangeCodeForToken(httpClient *http.Client, ep core.Endpoints,
	appId, appSecret, code, redirectURI string, errOut io.Writer) (*DeviceFlowResult, error) {

	tokenURL := ep.Open + PathOAuthTokenV2

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", appId)
	form.Set("client_secret", appSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	fmt.Fprintf(errOut, "[lark-cli] Exchanging authorization code for access token...\n")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: HTTP %d – %s", resp.StatusCode, string(body))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	accessToken := getStr(data, "access_token")
	if accessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}

	refreshToken := getStr(data, "refresh_token")
	tokenExpiresIn := getInt(data, "expires_in", 7200)
	refreshExpiresIn := getInt(data, "refresh_token_expires_in", 604800)
	if refreshToken == "" {
		fmt.Fprintf(errOut, "[lark-cli] [WARN] authcode-flow: no refresh_token in response\n")
		refreshExpiresIn = tokenExpiresIn
	}

	fmt.Fprintf(errOut, "[lark-cli] authcode-flow: token obtained successfully\n")
	return &DeviceFlowResult{
		OK: true,
		Token: &DeviceFlowTokenData{
			AccessToken:      accessToken,
			RefreshToken:     refreshToken,
			ExpiresIn:        tokenExpiresIn,
			RefreshExpiresIn: refreshExpiresIn,
			Scope:            getStr(data, "scope"),
		},
	}, nil
}

const authSuccessHTML = `<!DOCTYPE html>
<html>
<head><title>Authorization Successful</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #00b96b;">✓ Authorization Successful</h1>
<p>You can close this window and return to the terminal.</p>
</body>
</html>`

const authFailHTML = `<!DOCTYPE html>
<html>
<head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1 style="color: #f5222d;">✗ Authorization Failed</h1>
<p>Error: %s</p>
<p>Please return to the terminal for more information.</p>
</body>
</html>`

