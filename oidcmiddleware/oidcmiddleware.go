/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright 2023 Damian Peckett <damian@pecke.tt>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oidcmiddleware

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

// Options allows configuring the OpenID Connect middleware.
type Options struct {
	// IssuerURL is the URL of the OpenID Connect issuer.
	IssuerURL string
	// RedirectURL is the URL to redirect the user to after they've logged in.
	RedirectURL string
	// ClientID is the OAuth2 client ID.
	ClientID string
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string
	// MaxAge is how long the users session should be valid for.
	MaxAge *time.Duration
	// TLSClientConfig is the TLS configuration to use when connecting to the issuer.
	TLSClientConfig *tls.Config
	// DiscoverIssuerURL is whether to discover the issuer public URL using the OpenID Connect discovery endpoint.
	// This is required if connecting to the issuer on a private URL.
	DiscoverIssuerURL bool
}

// NewOIDCMiddleware returns an echo middleware that can be used to protect routes with OpenID Connect.
func NewOIDCMiddleware(ctx context.Context, e *echo.Echo, store sessions.Store, opts *Options) (echo.MiddlewareFunc, error) {
	issuerURL, err := url.Parse(opts.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer url: %w", err)
	}

	transport := http.DefaultTransport
	if opts.TLSClientConfig != nil {
		transport.(*http.Transport).TLSClientConfig = opts.TLSClientConfig
	}

	if opts.DiscoverIssuerURL {
		transport = &rewritingTransport{
			transport: transport,
			host:      issuerURL.Host,
		}

		ctx = oidc.ClientContext(ctx, &http.Client{
			Transport: transport,
		})

		publicIssuerURL, err := discoverIssuerURL(ctx, opts.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("failed to discover public issuer url: %w", err)
		}

		ctx = oidc.InsecureIssuerURLContext(ctx, publicIssuerURL)
	} else {
		ctx = oidc.ClientContext(ctx, &http.Client{
			Transport: transport,
		})
	}

	provider, err := oidc.NewProvider(ctx, opts.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get oidc provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  opts.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: opts.ClientID,
	})

	e.GET("/oauth2/auth", func(c echo.Context) error {
		// 1. Check if the user is already logged in.
		session, err := store.Get(c.Request(), opts.ClientID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to get/create session")
		}

		// If the user is already logged in, redirect them to the homepage.
		if _, ok := session.Values["email"]; ok {
			return c.Redirect(http.StatusFound, "/")
		}

		// 2. Generate a random state parameter and store it in the users session.
		state, err := generateState()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate state")
		}

		session.Values["state"] = state
		if err := session.Save(c.Request(), c.Response()); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
		}

		// 3. Redirect the user to the OAuth2 provider to login.
		return c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL(state))
	})

	e.GET("/oauth2/callback", func(c echo.Context) error {
		// 1. Verify the random state parameter.
		session, err := store.Get(c.Request(), opts.ClientID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
		}

		state, ok := session.Values["state"]
		if !ok || state == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing state parameter")
		}

		delete(session.Values, "state")
		if err := session.Save(c.Request(), c.Response()); err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to save session")
		}

		if c.QueryParam("state") != state.(string) {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid state parameter")
		}

		ctx := oidc.ClientContext(c.Request().Context(), &http.Client{
			Transport: transport,
		})

		// 2. Exchange the authorization code for an OAuth2 token.
		oauth2Token, err := oauth2Config.Exchange(ctx, c.QueryParam("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "failed to exchange token")
		}

		// 3. Extract, verify, and decode the ID token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return echo.NewHTTPError(http.StatusInternalServerError, "no id_token field in oauth2 token")
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusForbidden, "failed to verify ID Token")
		}

		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}

		if err := idToken.Claims(&claims); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to extract claims from ID Token")
		}

		// 4. Check that the users email has been verified.
		if !claims.EmailVerified {
			return echo.NewHTTPError(http.StatusForbidden, "email not verified")
		}

		// 5. Store the verified email address in the users session.
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400, // 24 hours
			HttpOnly: true,
			Secure:   c.Request().URL.Scheme == "https",
		}

		if opts.MaxAge != nil {
			session.Options.MaxAge = int(opts.MaxAge.Seconds())
		}

		session.Values["email"] = claims.Email

		// 6. Retrieve the original URL from the session and redirect the user.
		originalURL := session.Values["original_url"].(string)
		delete(session.Values, "original_url")

		if err := session.Save(c.Request(), c.Response()); err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "failed to save session")
		}

		return c.Redirect(http.StatusFound, originalURL)
	})

	isAuthenticated := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// 1. Check if the user is logged in.
			session, err := store.Get(c.Request(), opts.ClientID)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
			}

			email, ok := session.Values["email"]
			if !ok {
				// 2. Store the original URL in the session so we can redirect the user back to it after they've logged in.
				session.Values["original_url"] = c.Request().URL.String()
				if err := session.Save(c.Request(), c.Response()); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
				}

				// 3. Begin the OAuth2 login flow.
				return c.Redirect(http.StatusFound, "/oauth2/auth")
			}

			c.Set("email", email.(string))

			return next(c)
		}
	}

	return isAuthenticated, nil
}

func generateState() (string, error) {
	var stateBytes = make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(stateBytes), nil
}

// rewritingTransport is an http.RoundTripper that rewrites the host of all requests to a given host.
// this allows using private issuer URLs.
type rewritingTransport struct {
	transport http.RoundTripper
	host      string
}

func (t *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = t.host

	return t.transport.RoundTrip(req)
}

func discoverIssuerURL(ctx context.Context, issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuer url: %w", err)
	}

	u.Path = path.Join(u.Path, "/.well-known/openid-configuration")

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := getClient(ctx).Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get openid configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get openid configuration, unexpected status code: %d", resp.StatusCode)
	}

	var configJSON struct {
		Issuer string `json:"issuer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&configJSON); err != nil {
		return "", fmt.Errorf("failed to unmarshal openid configuration: %w", err)
	}

	return configJSON.Issuer, nil
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	}

	return http.DefaultClient
}
