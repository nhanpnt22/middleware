package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	middleware "github.com/nhanpnt22/middleware"
)

func main() {
	foundation, err := middleware.NewFoundationStrict(middleware.FoundationConfig{
		Codec: middleware.FuncBinaryTextCodec{
			CodecName: "identity-text",
			EncodeFn: func(raw []byte) (string, error) {
				return fmt.Sprintf("%x", raw), nil
			},
			DecodeFn: func(encoded string) ([]byte, error) {
				return []byte(encoded), nil
			},
		},
		Digest: middleware.FuncDigestProvider{
			DigestName: "sha256",
			DigestFn: func(input []byte) ([]byte, error) {
				sum := sha256.Sum256(input)
				return sum[:], nil
			},
		},
		Entropy:     rand.Reader,
		TokenBytes:  16,
		MaxIDLength: 128,
	})
	if err != nil {
		panic(err)
	}

	// For deterministic foundation wiring, use the digest + codec path.
	contentHash, err := foundation.ContentHash([]byte("hello"))
	if err != nil {
		panic(err)
	}

	// Token generation needs entropy; in production, pass crypto/rand.Reader.
	// This example keeps the focus on adapter wiring, so it prints the hash path only.
	fmt.Println("codec:", foundation.CodecName())
	fmt.Println("digest:", foundation.DigestName())
	fmt.Println("hash:", contentHash)
}
