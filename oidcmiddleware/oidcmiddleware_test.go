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

package oidcmiddleware_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/gpu-ninja/echo-oidc-middleware/oidcmiddleware"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCMiddleware(t *testing.T) {
	issuer, stopMockOIDCProvider, err := startMockOIDCProvider("")
	require.NoError(t, err)
	t.Cleanup(stopMockOIDCProvider)

	ctx := context.Background()

	store := &mockStore{}

	e := echo.New()

	maxAge := time.Hour
	opts := &oidcmiddleware.Options{
		IssuerURL:    issuer,
		RedirectURL:  "http://localhost:8080/oauth2/callback",
		ClientID:     "testClient",
		ClientSecret: "testSecret",
		MaxAge:       &maxAge,
	}

	authMiddleware, err := oidcmiddleware.NewAuthMiddleware(ctx, e, store, opts)
	require.NoError(t, err)

	t.Run("Middleware Adds Email to Context When Logged In", func(t *testing.T) {
		store.session = sessions.NewSession(store, opts.ClientID)
		store.session.Values["email"] = "demo@example.com"

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)

		err := authMiddleware(func(c echo.Context) error {
			return c.String(http.StatusOK, c.Get("email").(string))
		})(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "demo@example.com", rec.Body.String())
	})

	t.Run("Middleware Redirects to Auth When Not Logged In", func(t *testing.T) {
		store.session = nil

		req := httptest.NewRequest(http.MethodGet, "/myurl", nil)
		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)

		err := authMiddleware(func(c echo.Context) error {
			return c.String(http.StatusOK, "logged in")
		})(c)
		require.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/oauth2/auth", rec.Header().Get("Location"))

		// Check that we saved the original URL in the session.
		session, err := store.Get(req, opts.ClientID)
		require.NoError(t, err)

		assert.Equal(t, "/myurl", session.Values["original_url"])
	})

	t.Run("OAuth2 Auth Initiates Login Flow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
		rec := httptest.NewRecorder()

		store.session = sessions.NewSession(store, opts.ClientID)

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)

		authURL, err := url.Parse(rec.Header().Get("Location"))
		require.NoError(t, err)

		assert.Equal(t, issuer+"/oauth2/auth", authURL.Scheme+"://"+authURL.Host+authURL.Path)
	})

	t.Run("OAuth2 Callback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/callback", nil)
		rec := httptest.NewRecorder()

		store.session = sessions.NewSession(store, opts.ClientID)
		store.session.Values["state"] = "testState"
		store.session.Values["original_url"] = "/myurl"

		q := req.URL.Query()
		q.Set("state", "testState")
		req.URL.RawQuery = q.Encode()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/myurl", rec.Header().Get("Location"))
	})

	t.Run("OAuth2 Callback With Invalid State", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/callback", nil)
		rec := httptest.NewRecorder()

		store.session = sessions.NewSession(store, opts.ClientID)
		store.session.Values["state"] = "testState"

		q := req.URL.Query()
		q.Set("state", "invalidState")
		req.URL.RawQuery = q.Encode()

		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestOIDCMiddlewareWithPrivateURL(t *testing.T) {
	issuer, stopMockOIDCProvider, err := startMockOIDCProvider("https://auth.example.com")
	require.NoError(t, err)
	t.Cleanup(stopMockOIDCProvider)

	ctx := context.Background()

	store := &mockStore{}

	e := echo.New()

	maxAge := time.Hour
	opts := &oidcmiddleware.Options{
		IssuerURL:         issuer,
		RedirectURL:       "http://localhost:8080/oauth2/callback",
		ClientID:          "testClient",
		ClientSecret:      "testSecret",
		MaxAge:            &maxAge,
		DiscoverIssuerURL: true,
	}

	_, err = oidcmiddleware.NewAuthMiddleware(ctx, e, store, opts)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback", nil)
	rec := httptest.NewRecorder()

	store.session = sessions.NewSession(store, opts.ClientID)
	store.session.Values["state"] = "testState"
	store.session.Values["original_url"] = "/myurl"

	q := req.URL.Query()
	q.Set("state", "testState")
	req.URL.RawQuery = q.Encode()

	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/myurl", rec.Header().Get("Location"))
}

func startMockOIDCProvider(staticIssuerURL string) (string, func(), error) {
	type providerJSON struct {
		Issuer      string   `json:"issuer"`
		AuthURL     string   `json:"authorization_endpoint"`
		TokenURL    string   `json:"token_endpoint"`
		JWKSURL     string   `json:"jwks_uri"`
		UserInfoURL string   `json:"userinfo_endpoint"`
		Algorithms  []string `json:"id_token_signing_alg_values_supported"`
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate jwt signing key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	e := echo.New()
	e.Logger.SetLevel(log.OFF)
	e.HideBanner = true

	e.GET("/.well-known/openid-configuration", func(c echo.Context) error {
		var issuer string
		if staticIssuerURL != "" {
			_, port, err := net.SplitHostPort(c.Request().Host)
			if err != nil {
				return err
			}

			issuer = fmt.Sprintf("%s:%s", staticIssuerURL, port)
		} else {
			issuer = "http://" + c.Request().Host
		}

		openidConfiguration := providerJSON{
			Issuer:      issuer,
			AuthURL:     fmt.Sprintf("%s/oauth2/auth", issuer),
			TokenURL:    fmt.Sprintf("%s/oauth2/token", issuer),
			JWKSURL:     fmt.Sprintf("%s/oauth2/keys", issuer),
			UserInfoURL: fmt.Sprintf("%s/oauth2/userinfo", issuer),
			Algorithms:  []string{"RS256"},
		}

		return c.JSON(http.StatusOK, openidConfiguration)
	})

	e.GET("/oauth2/keys", func(c echo.Context) error {
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "123456789",
					"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
				},
			},
		}

		return c.JSON(http.StatusOK, jwks)
	})

	e.POST("/oauth2/token", func(c echo.Context) error {
		var issuer string
		if staticIssuerURL != "" {
			_, port, err := net.SplitHostPort(c.Request().Host)
			if err != nil {
				return err
			}

			issuer = fmt.Sprintf("%s:%s", staticIssuerURL, port)
		} else {
			issuer = "http://" + c.Request().Host
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":            issuer,
			"sub":            "1234567890",
			"aud":            "testClient",
			"email":          "demo@example.com",
			"email_verified": true,
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Unix() + 300,
		})

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, map[string]string{
			"access_token": "testAccessToken",
			"id_token":     signedToken,
		})
	})

	go func() {
		if err := e.Start("localhost:0"); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := e.Shutdown(ctx); err != nil {
			panic(err)
		}
	}

	time.Sleep(100 * time.Millisecond)

	return "http://" + e.Listener.Addr().String(), cleanup, nil
}

type mockStore struct {
	session *sessions.Session
}

func (s *mockStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	if s.session == nil {
		s.session = sessions.NewSession(s, name)
	}

	return s.session, nil
}

func (s *mockStore) New(r *http.Request, name string) (*sessions.Session, error) {
	s.session = sessions.NewSession(s, name)
	return s.session, nil
}

func (s *mockStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	s.session = session
	return nil
}
