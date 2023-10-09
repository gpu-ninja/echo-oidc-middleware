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
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

// Options allows configuring the OpenID Connect middleware.
type Options struct {
	// Issuer is the URL of the OpenID Connect issuer.
	Issuer string
	// RedirectURL is the URL to redirect the user to after they've logged in.
	RedirectURL string
	// ClientID is the OAuth2 client ID.
	ClientID string
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string
	// MaxAge is how long the users session should be valid for.
	MaxAge *time.Duration
}

// NewOIDCMiddleware returns an echo middleware that can be used to protect routes with OpenID Connect.
func NewOIDCMiddleware(ctx context.Context, e *echo.Echo, store sessions.Store, opts *Options) (echo.MiddlewareFunc, error) {
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
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

		// 2. Exchange the authorization code for an OAuth2 token.
		oauth2Token, err := oauth2Config.Exchange(c.Request().Context(), c.QueryParam("code"))
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "failed to exchange token")
		}

		// 3. Extract, verify, and decode the ID token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return echo.NewHTTPError(http.StatusInternalServerError, "no id_token field in oauth2 token")
		}

		idToken, err := verifier.Verify(c.Request().Context(), rawIDToken)
		if err != nil {
			return echo.NewHTTPError(http.StatusForbidden, "failed to verify ID Token")
		}

		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}

		if err := idToken.Claims(&claims); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to extract claims from ID Token")
		}

		// 4. Check that the users email has been verified.
		if !claims.Verified {
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
