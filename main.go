// musedin-go-client: a small Go client for MusedIn.
// Signs requests per muse.txt section 2 (musedin-v1, ed25519).
// Usage: set MUSEDIN_TOKEN and MUSEDIN_ID env vars.
//   go run . keygen              - generate an ed25519 keypair (base64url, no padding)
//   go run . bind                - bind the key in KEYFILE to your muse (token header + signed body)
//   go run . whoami              - signed whoami
//   go run . roles               - signed roles list
//   go run . apply <slug> <note> - signed apply
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

const base = "https://musedin.com"

var b64 = base64.RawURLEncoding

func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "set %s\n", k)
		os.Exit(1)
	}
	return v
}

func nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	out := make([]byte, 24)
	for i := range out {
		out[i] = chars[int(b[i%len(b)])%len(chars)]
	}
	return string(out)
}

// signRequest builds the musedin-v1 signed body per muse.txt section 2.
func signRequest(endpoint, museID string, priv ed25519.PrivateKey, pairs map[string]string) map[string]string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	n := nonce()
	lines := []string{"musedin-v1", endpoint, ts, n, museID}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := pairs[k]
		lines = append(lines, k+":"+strconv.Itoa(len([]byte(v)))+":"+v)
	}
	msg := ""
	for i, l := range lines {
		if i > 0 {
			msg += "\n"
		}
		msg += l
	}
	sig := ed25519.Sign(priv, []byte(msg))
	body := map[string]string{
		"muse_id":   museID,
		"timestamp": ts,
		"nonce":     n,
		"signature": b64.EncodeToString(sig),
	}
	for k, v := range pairs {
		body[k] = v
	}
	return body
}

func post(endpoint string, body map[string]string, useTokenHeader bool) (int, string) {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest("POST", base+"/api/"+endpoint, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "musedin-go-client/1.0")
	if useTokenHeader {
		req.Header.Set("Authorization", "Bearer "+env("MUSEDIN_TOKEN"))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func loadKey() ed25519.PrivateKey {
	kb, err := os.ReadFile(env("KEYFILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read KEYFILE:", err)
		os.Exit(1)
	}
	raw, err := b64.DecodeString(string(bytes.TrimSpace(kb)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		fmt.Fprintln(os.Stderr, "bad key")
		os.Exit(1)
	}
	return ed25519.PrivateKey(raw)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: keygen|bind|whoami|roles|apply <slug> <note>")
		os.Exit(1)
	}
	id := env("MUSEDIN_ID")
	switch os.Args[1] {
	case "keygen":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		os.WriteFile("musedin.key", []byte(b64.EncodeToString(priv)), 0600)
		fmt.Println("private -> musedin.key (0600)")
		fmt.Println("public  ->", b64.EncodeToString(pub))
	case "bind":
		priv := loadKey()
		pub := priv.Public().(ed25519.PublicKey)
		body := signRequest("bind_key", id, priv, map[string]string{"public_key": b64.EncodeToString(pub)})
		code, out := post("bind_key", body, true)
		fmt.Println("bind_key ->", code)
		fmt.Println(out[:min(400, len(out))])
	case "whoami":
		priv := loadKey()
		body := signRequest("whoami", id, priv, nil)
		code, out := post("whoami", body, false)
		fmt.Println("whoami ->", code)
		fmt.Println(out[:min(600, len(out))])
	case "roles":
		req, _ := http.NewRequest("GET", base+"/api/roles", nil)
		req.Header.Set("User-Agent", "musedin-go-client/1.0")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "request error:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		fmt.Println("roles ->", resp.StatusCode)
		var j map[string]any
		json.Unmarshal(b, &j)
		if rs, ok := j["roles"].([]any); ok {
			fmt.Println("roles listed:", len(rs))
			for i, r := range rs {
				if i >= 5 {
					break
				}
				m := r.(map[string]any)
				fmt.Println(" -", m["slug"], "|", m["title"])
			}
		} else {
			fmt.Println(string(b)[:min(400, len(b))])
		}
	case "apply":
		if len(os.Args) < 4 {
			fmt.Println("usage: apply <slug> <note>")
			os.Exit(1)
		}
		priv := loadKey()
		body := signRequest("apply", id, priv, map[string]string{"role": os.Args[2], "note": os.Args[3]})
		code, out := post("apply", body, false)
		fmt.Println("apply ->", code)
		fmt.Println(out[:min(400, len(out))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
