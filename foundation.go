package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"
)

const defaultFoundationTokenBytes = 16

const errFoundationRequired = "foundation is required"

// BinaryTextCodec converts raw bytes to transport-safe text and back.
// Implementations can wrap B57/F57, Base64URL, Base32, or custom alphabets.
type BinaryTextCodec interface {
	Name() string
	Encode(raw []byte) (string, error)
	Decode(encoded string) ([]byte, error)
}

// DigestProvider produces deterministic digests over input bytes.
type DigestProvider interface {
	Name() string
	Digest(input []byte) ([]byte, error)
}

// FoundationConfig wires deterministic ID and token generation primitives.
type FoundationConfig struct {
	Codec       BinaryTextCodec
	Digest      DigestProvider
	Entropy     io.Reader
	TokenBytes  int
	MaxIDLength int
}

// Foundation exposes reusable primitives for middleware and service wiring.
type Foundation struct {
	codec       BinaryTextCodec
	digest      DigestProvider
	entropy     io.Reader
	tokenBytes  int
	maxIDLength int
}

// NewFoundation uses safe defaults (SHA-256 + Base64URL + crypto/rand).
func NewFoundation() *Foundation {
	f, _ := NewFoundationStrict(FoundationConfig{
		Codec:       Base64URLCodec{},
		Digest:      SHA256Digest{},
		Entropy:     rand.Reader,
		TokenBytes:  defaultFoundationTokenBytes,
		MaxIDLength: 256,
	})
	return f
}

// NewFoundationStrict creates a foundation instance without implicit defaults.
func NewFoundationStrict(cfg FoundationConfig) (*Foundation, error) {
	if err := ValidateFoundationConfigStrict(cfg); err != nil {
		return nil, err
	}

	return &Foundation{
		codec:       cfg.Codec,
		digest:      cfg.Digest,
		entropy:     cfg.Entropy,
		tokenBytes:  cfg.TokenBytes,
		maxIDLength: cfg.MaxIDLength,
	}, nil
}

// CodecName returns the configured codec identifier for observability.
func (f *Foundation) CodecName() string {
	if f == nil || f.codec == nil {
		return ""
	}
	return f.codec.Name()
}

// DigestName returns the configured digest identifier for observability.
func (f *Foundation) DigestName() string {
	if f == nil || f.digest == nil {
		return ""
	}
	return f.digest.Name()
}

// NewToken creates a random, transport-safe token using configured entropy and codec.
func (f *Foundation) NewToken() (string, error) {
	if f == nil {
		return "", fmt.Errorf(errFoundationRequired)
	}

	raw := make([]byte, f.tokenBytes)
	if _, err := io.ReadFull(f.entropy, raw); err != nil {
		return "", err
	}

	encoded, err := f.codec.Encode(raw)
	if err != nil {
		return "", err
	}
	if len(encoded) > f.maxIDLength {
		return "", fmt.Errorf("encoded token exceeds max length %d", f.maxIDLength)
	}
	return encoded, nil
}

// ContentHash computes digest(input) then encodes it into text.
func (f *Foundation) ContentHash(input []byte) (string, error) {
	if f == nil {
		return "", fmt.Errorf(errFoundationRequired)
	}

	digest, err := f.digest.Digest(input)
	if err != nil {
		return "", err
	}
	encoded, err := f.codec.Encode(digest)
	if err != nil {
		return "", err
	}
	if len(encoded) > f.maxIDLength {
		return "", fmt.Errorf("encoded hash exceeds max length %d", f.maxIDLength)
	}
	return encoded, nil
}

// DeterministicID builds a namespaced stable ID with optional digest-byte truncation.
func (f *Foundation) DeterministicID(namespace string, payload []byte, digestBytes int) (string, error) {
	if f == nil {
		return "", fmt.Errorf(errFoundationRequired)
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		return "", fmt.Errorf("namespace is required")
	}
	if digestBytes < 0 {
		return "", fmt.Errorf("digestBytes must be >= 0")
	}

	input := append([]byte(ns), 0)
	input = append(input, payload...)
	digest, err := f.digest.Digest(input)
	if err != nil {
		return "", err
	}
	if digestBytes > 0 {
		if digestBytes > len(digest) {
			return "", fmt.Errorf("digestBytes %d exceeds digest length %d", digestBytes, len(digest))
		}
		digest = digest[:digestBytes]
	}

	encoded, err := f.codec.Encode(digest)
	if err != nil {
		return "", err
	}
	if len(encoded) > f.maxIDLength {
		return "", fmt.Errorf("encoded deterministic id exceeds max length %d", f.maxIDLength)
	}
	return encoded, nil
}

// Base64URLCodec is a dependency-free default codec.
type Base64URLCodec struct{}

func (Base64URLCodec) Name() string { return "base64url" }

func (Base64URLCodec) Encode(raw []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (Base64URLCodec) Decode(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

// SHA256Digest is a dependency-free default digest provider.
type SHA256Digest struct{}

func (SHA256Digest) Name() string { return "sha256" }

func (SHA256Digest) Digest(input []byte) ([]byte, error) {
	sum := sha256.Sum256(input)
	return sum[:], nil
}

// HashDigestProvider adapts any hash.Hash constructor into a DigestProvider.
type HashDigestProvider struct {
	Algorithm string
	New       func() hash.Hash
}

func (p HashDigestProvider) Name() string { return strings.TrimSpace(p.Algorithm) }

func (p HashDigestProvider) Digest(input []byte) ([]byte, error) {
	if p.New == nil {
		return nil, fmt.Errorf("hash digest provider: New is required")
	}
	h := p.New()
	if _, err := h.Write(input); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// FuncBinaryTextCodec adapts function pairs into a BinaryTextCodec.
type FuncBinaryTextCodec struct {
	CodecName string
	EncodeFn  func([]byte) (string, error)
	DecodeFn  func(string) ([]byte, error)
}

func (c FuncBinaryTextCodec) Name() string { return strings.TrimSpace(c.CodecName) }

func (c FuncBinaryTextCodec) Encode(raw []byte) (string, error) {
	if c.EncodeFn == nil {
		return "", fmt.Errorf("binary text codec: EncodeFn is required")
	}
	return c.EncodeFn(raw)
}

func (c FuncBinaryTextCodec) Decode(encoded string) ([]byte, error) {
	if c.DecodeFn == nil {
		return nil, fmt.Errorf("binary text codec: DecodeFn is required")
	}
	return c.DecodeFn(encoded)
}

// FuncDigestProvider adapts a function into a DigestProvider.
type FuncDigestProvider struct {
	DigestName string
	DigestFn   func([]byte) ([]byte, error)
}

func (p FuncDigestProvider) Name() string { return strings.TrimSpace(p.DigestName) }

func (p FuncDigestProvider) Digest(input []byte) ([]byte, error) {
	if p.DigestFn == nil {
		return nil, fmt.Errorf("digest provider: DigestFn is required")
	}
	return p.DigestFn(input)
}
