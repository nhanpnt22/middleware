package middleware

import (
	"bytes"
	"errors"
	"testing"
)

type staticDigestProvider struct {
	name   string
	output []byte
	err    error
}

func (s staticDigestProvider) Name() string { return s.name }

func (s staticDigestProvider) Digest([]byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.output...), nil
}

type staticCodec struct {
	name      string
	lastInput []byte
}

func (s *staticCodec) Name() string { return s.name }

func (s *staticCodec) Encode(raw []byte) (string, error) {
	s.lastInput = append([]byte(nil), raw...)
	return string(raw), nil
}

func (s *staticCodec) Decode(encoded string) ([]byte, error) {
	return []byte(encoded), nil
}

func TestFoundationStrictValidation(t *testing.T) {
	err := ValidateFoundationConfigStrict(FoundationConfig{})
	if err == nil {
		t.Fatalf("expected strict validation error for empty config")
	}

	err = ValidateFoundationConfigStrict(FoundationConfig{
		Codec:       Base64URLCodec{},
		Digest:      SHA256Digest{},
		Entropy:     bytes.NewReader(make([]byte, 64)),
		TokenBytes:  16,
		MaxIDLength: 128,
	})
	if err != nil {
		t.Fatalf("expected valid strict config, got %v", err)
	}
}

func TestNewFoundationDefault(t *testing.T) {
	f := NewFoundation()
	if f == nil {
		t.Fatalf("expected default foundation")
	}
	if f.CodecName() == "" {
		t.Fatalf("expected codec name")
	}
	if f.DigestName() == "" {
		t.Fatalf("expected digest name")
	}
}

func TestFoundationNewToken(t *testing.T) {
	f, err := NewFoundationStrict(FoundationConfig{
		Codec:       Base64URLCodec{},
		Digest:      SHA256Digest{},
		Entropy:     bytes.NewReader([]byte("0123456789abcdef0123456789abcdef")),
		TokenBytes:  16,
		MaxIDLength: 128,
	})
	if err != nil {
		t.Fatalf("strict constructor failed: %v", err)
	}

	token, err := f.NewToken()
	if err != nil {
		t.Fatalf("token generation failed: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}
}

func TestFoundationDeterministicID(t *testing.T) {
	codec := &staticCodec{name: "static"}
	f, err := NewFoundationStrict(FoundationConfig{
		Codec:       codec,
		Digest:      staticDigestProvider{name: "fixed", output: []byte{1, 2, 3, 4, 5}},
		Entropy:     bytes.NewReader(make([]byte, 64)),
		TokenBytes:  8,
		MaxIDLength: 64,
	})
	if err != nil {
		t.Fatalf("strict constructor failed: %v", err)
	}

	id, err := f.DeterministicID("orders", []byte("payload"), 3)
	if err != nil {
		t.Fatalf("deterministic id failed: %v", err)
	}
	if id == "" {
		t.Fatalf("expected non-empty deterministic id")
	}
	if !bytes.Equal(codec.lastInput, []byte{1, 2, 3}) {
		t.Fatalf("expected truncated digest bytes, got %v", codec.lastInput)
	}
}

func TestFoundationContentHashDigestError(t *testing.T) {
	f, err := NewFoundationStrict(FoundationConfig{
		Codec:       Base64URLCodec{},
		Digest:      staticDigestProvider{name: "broken", err: errors.New("boom")},
		Entropy:     bytes.NewReader(make([]byte, 64)),
		TokenBytes:  8,
		MaxIDLength: 64,
	})
	if err != nil {
		t.Fatalf("strict constructor failed: %v", err)
	}

	_, err = f.ContentHash([]byte("abc"))
	if err == nil {
		t.Fatalf("expected digest error")
	}
}

func TestFoundationDeterministicIDValidation(t *testing.T) {
	f, err := NewFoundationStrict(FoundationConfig{
		Codec:       Base64URLCodec{},
		Digest:      SHA256Digest{},
		Entropy:     bytes.NewReader(make([]byte, 64)),
		TokenBytes:  8,
		MaxIDLength: 64,
	})
	if err != nil {
		t.Fatalf("strict constructor failed: %v", err)
	}

	if _, err := f.DeterministicID("", []byte("payload"), 0); err == nil {
		t.Fatalf("expected namespace validation error")
	}
	if _, err := f.DeterministicID("ns", []byte("payload"), -1); err == nil {
		t.Fatalf("expected negative digestBytes validation error")
	}
	if _, err := f.DeterministicID("ns", []byte("payload"), 128); err == nil {
		t.Fatalf("expected digestBytes overflow validation error")
	}
}

func TestFuncAdapters(t *testing.T) {
	codec := FuncBinaryTextCodec{
		CodecName: "func-codec",
		EncodeFn: func(raw []byte) (string, error) {
			return string(raw), nil
		},
		DecodeFn: func(encoded string) ([]byte, error) {
			return []byte(encoded), nil
		},
	}
	encoded, err := codec.Encode([]byte("abc"))
	if err != nil || encoded != "abc" {
		t.Fatalf("unexpected codec encode result: %q, %v", encoded, err)
	}

	digest := FuncDigestProvider{
		DigestName: "func-digest",
		DigestFn: func(input []byte) ([]byte, error) {
			return append([]byte("x"), input...), nil
		},
	}
	out, err := digest.Digest([]byte("abc"))
	if err != nil {
		t.Fatalf("unexpected digest error: %v", err)
	}
	if string(out) != "xabc" {
		t.Fatalf("unexpected digest result: %q", string(out))
	}
}
