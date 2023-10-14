# echo-oidc-middleware

A basic OpenID Connect authentication middleware for LabStack Echo.

## Usage

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/gpu-ninja/echo-oidc-middleware/oidcmiddleware"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

	opts := &oidcmiddleware.Options{
		IssuerURL:    "https://accounts.google.com",
		RedirectURL:  "http://localhost:8080/oauth2/callback",
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	ctx := context.Background()
	authMiddleware, err := oidcmiddleware.NewAuthMiddleware(ctx, e, store, opts)
	if err != nil {
		log.Fatal(err)
	}

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	}, authMiddleware)

	// In production you should use TLS.
	e.Logger.Fatal(e.Start(":8080"))
}
```