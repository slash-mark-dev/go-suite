package sumdb

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const algEd25519 = 1

// Verifier checks signatures from one key.
type Verifier struct {
	Name    string
	KeyHash uint32
	pub     ed25519.PublicKey
}

// Signer signs notes (used by the test server).
type Signer struct {
	Name    string
	KeyHash uint32
	priv    ed25519.PrivateKey
}

func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

// NewVerifier parses a verifier key "name+hash+base64key".
func NewVerifier(vkey string) (*Verifier, error) {
	name, vkey, ok1 := strings.Cut(vkey, "+")
	hash16, key64, ok2 := strings.Cut(vkey, "+")
	h, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if !ok1 || !ok2 || err1 != nil || err2 != nil || len(hash16) != 8 || !isValidName(name) || len(key) == 0 {
		return nil, errors.New("malformed verifier key")
	}
	if uint32(h) != keyHash(name, key) {
		return nil, errors.New("verifier key hash mismatch")
	}
	if key[0] != algEd25519 || len(key) != 1+ed25519.PublicKeySize {
		return nil, errors.New("unknown verifier algorithm")
	}
	return &Verifier{Name: name, KeyHash: uint32(h), pub: ed25519.PublicKey(key[1:])}, nil
}

// NewSigner parses a signer key "PRIVATE+KEY+name+hash+base64key".
func NewSigner(skey string) (*Signer, error) {
	priv1, skey, _ := strings.Cut(skey, "+")
	priv2, skey, _ := strings.Cut(skey, "+")
	name, skey, _ := strings.Cut(skey, "+")
	hash16, key64, _ := strings.Cut(skey, "+")
	h, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err1 != nil || err2 != nil || !isValidName(name) || len(key) == 0 {
		return nil, errors.New("malformed signer key")
	}
	if key[0] != algEd25519 || len(key) != 1+ed25519.SeedSize {
		return nil, errors.New("unknown signer algorithm")
	}
	pub := ed25519.NewKeyFromSeed(key[1:]).Public().(ed25519.PublicKey)
	if uint32(h) != keyHash(name, append([]byte{algEd25519}, pub...)) {
		return nil, errors.New("invalid signer key hash")
	}
	return &Signer{Name: name, KeyHash: uint32(h), priv: ed25519.NewKeyFromSeed(key[1:])}, nil
}

// GenerateKey creates a new signer/verifier key pair.
func GenerateKey(rand io.Reader, name string) (skey, vkey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return "", "", err
	}
	pubkey := append([]byte{algEd25519}, pub...)
	privkey := append([]byte{algEd25519}, priv.Seed()...)
	h := keyHash(name, pubkey)
	skey = fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(privkey))
	vkey = fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(pubkey))
	return skey, vkey, nil
}

// Note is a verified signed note.
type Note struct {
	Text string
}

// Sign signs text (which must end in a newline) and returns the note.
func (s *Signer) Sign(text string) ([]byte, error) {
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("malformed note")
	}
	sig := ed25519.Sign(s.priv, []byte(text))
	var hbuf [4]byte
	binary.BigEndian.PutUint32(hbuf[:], s.KeyHash)
	b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sig...))
	var buf bytes.Buffer
	buf.WriteString(text)
	buf.WriteString("\n")
	fmt.Fprintf(&buf, "— %s %s\n", s.Name, b64)
	return buf.Bytes(), nil
}

var sigPrefix = []byte("— ")

// OpenNote verifies a signed note against v. At least one valid signature by
// v is required; signatures by unknown keys are ignored.
func OpenNote(msg []byte, v *Verifier) (*Note, error) {
	if !utf8.Valid(msg) {
		return nil, errors.New("malformed note")
	}
	split := bytes.LastIndex(msg, []byte("\n\n"))
	if split < 0 {
		return nil, errors.New("malformed note")
	}
	text, sigs := msg[:split+1], msg[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errors.New("malformed note")
	}
	verified := false
	for len(sigs) > 0 {
		i := bytes.IndexByte(sigs, '\n')
		line := sigs[:i]
		sigs = sigs[i+1:]
		if !bytes.HasPrefix(line, sigPrefix) {
			return nil, errors.New("malformed note")
		}
		line = line[len(sigPrefix):]
		name, b64, ok := strings.Cut(string(line), " ")
		sig, err := base64.StdEncoding.DecodeString(b64)
		if !ok || err != nil || !isValidName(name) || b64 == "" || len(sig) < 5 {
			return nil, errors.New("malformed note")
		}
		hash := binary.BigEndian.Uint32(sig[0:4])
		if name != v.Name || hash != v.KeyHash {
			continue
		}
		if !ed25519.Verify(v.pub, text, sig[4:]) {
			return nil, fmt.Errorf("invalid signature for key %s+%08x", name, hash)
		}
		verified = true
	}
	if !verified {
		return nil, fmt.Errorf("note has no verifiable signatures from %s", v.Name)
	}
	return &Note{Text: string(text)}, nil
}

// Tree is a signed tree head.
type Tree struct {
	N    int64
	Hash Hash
}

// ParseTree parses the text of a tree note ("go.sum database tree\nN\nhash\n").
func ParseTree(text []byte) (Tree, error) {
	if !bytes.HasPrefix(text, []byte("go.sum database tree\n")) {
		return Tree{}, errors.New("malformed tree note")
	}
	lines := strings.SplitN(string(text), "\n", 5)
	if len(lines) < 4 {
		return Tree{}, errors.New("malformed tree note")
	}
	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || lines[1] != strconv.FormatInt(n, 10) {
		return Tree{}, errors.New("malformed tree note")
	}
	h, err := ParseHash(lines[2])
	if err != nil {
		return Tree{}, errors.New("malformed tree note")
	}
	return Tree{N: n, Hash: h}, nil
}

// FormatTree formats a tree note text.
func FormatTree(t Tree) []byte {
	return []byte(fmt.Sprintf("go.sum database tree\n%d\n%s\n", t.N, t.Hash))
}
