//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/opensecstack/sdk/go/sinauth"
)

func main() {
	client, err := sinauth.New("https://auth.sin.to")
	if err != nil {
		log.Fatal(err)
	}

	// Verify a token
	claims, err := client.VerifyTokenForClient(context.Background(), "eyJ...", "community")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user: %s roles: %v\n", claims.Sub, claims.ClientRoles)

	// Use as middleware
	mux := http.NewServeMux()
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		claims, _ := sinauth.ClaimsFromContext(r.Context())
		fmt.Fprintf(w, "hello %s", claims.Sub)
	})
	http.ListenAndServe(":8080", client.BearerAuth(mux))
}
