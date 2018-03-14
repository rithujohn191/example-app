package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
)

var (
	clientID     = os.Getenv("GOOGLE_OAUTH2_CLIENT_ID")
	clientSecret = os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET")
)

type Authenticator struct {
	provider     *oidc.Provider
	clientConfig oauth2.Config
	ctx          context.Context
}

func newAuthenticator() (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatalf("failed to get provider: %v", err)
	}

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Authenticator{
		provider:     provider,
		clientConfig: config,
		ctx:          ctx,
	}, nil
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != "state" {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	token, err := a.clientConfig.Exchange(a.ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	idToken, err := a.provider.Verifier(oidcConfig).Verify(a.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage
	}{token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func main() {
	auther, err := newAuthenticator()
	if err != nil {
		log.Fatalf("failed to get authenticator: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, auther.clientConfig.AuthCodeURL("state"), http.StatusFound)
	})

	mux.HandleFunc("/auth/google/callback", auther.handleCallback)

	log.Fatal(http.ListenAndServe("127.0.0.1:5556", mux))
}
