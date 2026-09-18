// tarako-attester serves nonce-bound Tarako Quotes over HTTP.
package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	tarakoHello     = uintptr(0x00005300)
	tarakoGetPubkey = uintptr(0x80215301)
	tarakoSignData  = uintptr(0xC1015302)
	userDataBytes   = 128
)

var bindingDomain = []byte("TARAKO-TQ-REQUEST-V1\x00")

type quoteRequest struct {
	Request string `json:"request"`
	Nonce   string `json:"nonce"`
}

type bindingContext struct {
	Nonce   string `json:"nonce"`
	Request string `json:"request"`
}

type quoteResponse struct {
	Hash         string `json:"hash"`
	PublicKey    string `json:"public_key"`
	SignatureDER string `json:"signature_der"`
	UserData     string `json:"user_data"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type signDataRequest struct {
	UserData [userDataBytes]byte
	Hash     [32]byte
	SigR     [32]byte
	SigS     [32]byte
	Pubkey   [33]byte
}

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

func ioctl(fd uintptr, request uintptr, argument uintptr) (uintptr, error) {
	result, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, argument)
	if errno != 0 {
		return 0, errno
	}
	return result, nil
}

func requestBinding(request quoteRequest) ([]byte, error) {
	nonce, err := hex.DecodeString(request.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) != 32 {
		return nil, errors.New("nonce must be 32 bytes")
	}
	if request.Request == "" {
		return nil, errors.New("request must not be empty")
	}
	context, err := json.Marshal(bindingContext{
		Nonce:   request.Nonce,
		Request: request.Request,
	})
	if err != nil {
		return nil, fmt.Errorf("encode request context: %w", err)
	}
	hasher := sha256.New()
	hasher.Write(bindingDomain)
	hasher.Write(context)
	return hasher.Sum(nil), nil
}

func tarakoQuote(binding []byte) (*quoteResponse, error) {
	device, err := os.OpenFile("/dev/tarako", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/tarako: %w", err)
	}
	defer device.Close()

	fd := device.Fd()
	result, err := ioctl(fd, tarakoHello, 0)
	if err != nil {
		return nil, fmt.Errorf("TARAKO_HELLO: %w", err)
	}
	if result != 0 {
		return nil, fmt.Errorf("TARAKO_HELLO returned %d", result)
	}

	var publicKey [33]byte
	result, err = ioctl(fd, tarakoGetPubkey, uintptr(unsafe.Pointer(&publicKey[0])))
	runtime.KeepAlive(&publicKey)
	if err != nil {
		return nil, fmt.Errorf("TARAKO_GET_PUBKEY: %w", err)
	}
	if result != uintptr(len(publicKey)) {
		return nil, fmt.Errorf("TARAKO_GET_PUBKEY returned %d", result)
	}

	var signingRequest signDataRequest
	copy(signingRequest.UserData[:], binding)
	result, err = ioctl(fd, tarakoSignData, uintptr(unsafe.Pointer(&signingRequest)))
	runtime.KeepAlive(&signingRequest)
	if err != nil {
		return nil, fmt.Errorf("TARAKO_SIGN_DATA: %w", err)
	}
	if result != 0 {
		return nil, fmt.Errorf("TARAKO_SIGN_DATA returned %d", result)
	}
	if signingRequest.Pubkey != publicKey {
		return nil, errors.New("TAK public key changed between ioctls")
	}

	signatureDER, err := asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(signingRequest.SigR[:]),
		S: new(big.Int).SetBytes(signingRequest.SigS[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode ECDSA signature: %w", err)
	}

	return &quoteResponse{
		Hash:         hex.EncodeToString(signingRequest.Hash[:]),
		PublicKey:    hex.EncodeToString(publicKey[:]),
		SignatureDER: hex.EncodeToString(signatureDER),
		UserData:     hex.EncodeToString(signingRequest.UserData[:]),
	}, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func quoteHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeJSON(writer, http.StatusMethodNotAllowed, errorResponse{"POST required"})
		return
	}
	var input quoteRequest
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	binding, err := requestBinding(input)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, errorResponse{err.Error()})
		return
	}
	quote, err := tarakoQuote(binding)
	if err != nil {
		log.Printf("Tarako Quote failed: %v", err)
		writeJSON(writer, http.StatusInternalServerError, errorResponse{err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, quote)
}

func main() {
	listen := flag.String("listen", ":5000", "HTTP listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/quote", quoteHandler)
	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("listening on %s", *listen)
	log.Fatal(server.ListenAndServe())
}
