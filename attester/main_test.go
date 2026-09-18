package main

import (
	"encoding/hex"
	"testing"
	"unsafe"
)

func TestRequestBindingMatchesVerifierProfile(t *testing.T) {
	request := quoteRequest{
		Request: "repeatable-client-request",
		Nonce:   "0000000000000000000000000000000000000000000000000000000000000000",
	}
	binding, err := requestBinding(request)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "21874ef909af0728a9b2deaa3ab269fa114276fda8ea8535e24046ad90a4bfc9"
	if hex.EncodeToString(binding) != expected {
		t.Fatalf("binding = %x, want %s", binding, expected)
	}
}

func TestRequestBindingRejectsInvalidNonce(t *testing.T) {
	_, err := requestBinding(quoteRequest{Request: "request", Nonce: "00"})
	if err == nil {
		t.Fatal("short nonce was accepted")
	}
}

func TestSignDataRequestMatchesKernelABI(t *testing.T) {
	if size := unsafe.Sizeof(signDataRequest{}); size != 257 {
		t.Fatalf("signDataRequest size = %d, want 257", size)
	}
}
