// Package keygen implements the `citadel keygen` CLI subcommand: generating
// a personal Ed25519 keypair for an Operator or Verifier under the
// self-custody model described in adrs/004-operator-verifier-ed25519-signatures.md.
//
// CITADEL never sees or stores a private key — the private key file
// produced here stays on the operator's machine; only the public key is
// ever sent to CITADEL, via POST /api/v1/keys/register.
package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Run implements `citadel keygen [-out DIR] [-label NAME]`. args excludes
// the "keygen" subcommand token itself (i.e. os.Args[2:]).
func Run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", ".", "directory to write the private key file into")
	label := fs.String("label", "citadel", "key label, used as the file name and the default key_id")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: generating Ed25519 keypair: %w", err)
	}

	keyPath := filepath.Join(*out, *label+".key")
	if _, statErr := os.Stat(keyPath); statErr == nil {
		return fmt.Errorf("keygen: %s already exists — refusing to overwrite a private key", keyPath)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("keygen: writing private key file: %w", err)
	}

	pubHex := hex.EncodeToString(pub)

	fmt.Fprintf(stdout, "Private key written to %s (mode 0600 — keep this local, never share or commit it).\n\n", keyPath)
	fmt.Fprintf(stdout, "Public key (hex): %s\n\n", pubHex)
	fmt.Fprintf(stdout, "Register it against your sinauth user_id with a live sinauth access token:\n\n")
	fmt.Fprintf(stdout, "  curl -X POST https://<citadel-host>/api/v1/keys/register \\\n")
	fmt.Fprintf(stdout, "    -H 'Content-Type: application/json' \\\n")
	fmt.Fprintf(stdout, "    -d '{\"user_id\": \"<YOUR_SINAUTH_USER_UUID>\", \"token\": \"<YOUR_SINAUTH_ACCESS_TOKEN>\", \"key_id\": %q, \"public_key\": %q}'\n",
		*label, pubHex)

	return nil
}
