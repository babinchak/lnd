package brontidefuzz

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	initBytes = []byte{
		0x81, 0xb6, 0x37, 0xd8, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x96, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe4, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xfd, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	respBytes = []byte{
		0xaa, 0xb6, 0x37, 0xd9, 0xfc, 0xd2, 0xc6, 0xda,
		0x63, 0x59, 0xe6, 0x99, 0x31, 0x13, 0xa1, 0x17,
		0xd, 0xe7, 0x95, 0xe9, 0xb7, 0x25, 0xb8, 0x4d,
		0x1e, 0xb, 0x4c, 0xf9, 0x9e, 0xc5, 0x8c, 0xe9,
	}

	// Returns the initiator's ephemeral private key.
	initEphemeral = brontide.EphemeralGenerator(func() (*btcec.PrivateKey, error) {
		e := "121212121212121212121212121212121212121212121212121212" +
			"1212121212"
		eBytes, err := hex.DecodeString(e)
		if err != nil {
			return nil, err
		}

		priv, _ := btcec.PrivKeyFromBytes(eBytes)
		return priv, nil
	})

	// Returns the responder's ephemeral private key.
	respEphemeral = brontide.EphemeralGenerator(func() (*btcec.PrivateKey, error) {
		e := "222222222222222222222222222222222222222222222222222" +
			"2222222222222"
		eBytes, err := hex.DecodeString(e)
		if err != nil {
			return nil, err
		}

		priv, _ := btcec.PrivKeyFromBytes(eBytes)
		return priv, nil
	})
)

// completeHandshake takes two brontide machines (initiator, responder)
// and completes the brontide handshake between them. If any part of the
// handshake fails, this function will panic.
func completeHandshake(initiator, responder *brontide.Machine) {
	if err := handshake(initiator, responder); err != nil {
		nilAndPanic(initiator, responder, err)
	}
}

// handshake actually completes the brontide handshake and bubbles up
// an error to the calling function.
func handshake(initiator, responder *brontide.Machine) error {
	// Generate ActOne and send to the responder.
	actOne, err := initiator.GenActOne()
	if err != nil {
		return err
	}

	if err := responder.RecvActOne(actOne); err != nil {
		return err
	}

	// Generate ActTwo and send to initiator.
	actTwo, err := responder.GenActTwo()
	if err != nil {
		return err
	}

	if err := initiator.RecvActTwo(actTwo); err != nil {
		return err
	}

	// Generate ActThree and send to responder.
	actThree, err := initiator.GenActThree()
	if err != nil {
		return err
	}

	return responder.RecvActThree(actThree)
}

// nilAndPanic first nils the initiator and responder's Curve fields and then
// panics.
func nilAndPanic(initiator, responder *brontide.Machine, err error) {
	panic(fmt.Errorf("error: %v, initiator: %v, responder: %v", err,
		spew.Sdump(initiator), spew.Sdump(responder)))
}

// getBrontideMachines returns two brontide machines that use random keys
// everywhere.
func getBrontideMachines() (*brontide.Machine, *brontide.Machine) {
	initPriv, _ := btcec.NewPrivateKey()
	respPriv, _ := btcec.NewPrivateKey()
	respPub := (*btcec.PublicKey)(&respPriv.PublicKey)

	initPrivECDH := &keychain.PrivKeyECDH{PrivKey: initPriv}
	respPrivECDH := &keychain.PrivKeyECDH{PrivKey: respPriv}

	initiator := brontide.NewBrontideMachine(true, initPrivECDH, respPub)
	responder := brontide.NewBrontideMachine(false, respPrivECDH, nil)

	return initiator, responder
}

// getStaticBrontideMachines returns two brontide machines that use static keys
// everywhere.
func getStaticBrontideMachines() (*brontide.Machine, *brontide.Machine) {
	initPriv, _ := btcec.PrivKeyFromBytes(initBytes)
	respPriv, respPub := btcec.PrivKeyFromBytes(respBytes)

	initPrivECDH := &keychain.PrivKeyECDH{PrivKey: initPriv}
	respPrivECDH := &keychain.PrivKeyECDH{PrivKey: respPriv}

	initiator := brontide.NewBrontideMachine(
		true, initPrivECDH, respPub, initEphemeral,
	)
	responder := brontide.NewBrontideMachine(
		false, respPrivECDH, nil, respEphemeral,
	)

	return initiator, responder
}

// Fuzz_random_actone is a go-fuzz harness for ActOne in the brontide
// handshake.
func Fuzz_random_actone(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActOneSize {
		return 1
	}

	// This will return brontide machines with random keys.
	_, responder := getBrontideMachines()

	// Copy data into [ActOneSize]byte.
	var actOne [brontide.ActOneSize]byte
	copy(actOne[:], data)

	// Responder receives ActOne, should fail on the MAC check.
	if err := responder.RecvActOne(actOne); err == nil {
		nilAndPanic(nil, responder, nil)
	}

	return 1
}

// Fuzz_random_actthree is a go-fuzz harness for ActThree in the brontide
// handshake.
func Fuzz_random_actthree(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActThreeSize {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Generate ActOne and send to the responder.
	actOne, err := initiator.GenActOne()
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Receiving ActOne should succeed, so we panic on error.
	if err := responder.RecvActOne(actOne); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Generate ActTwo - this is not sent to the initiator because nothing is
	// done with the initiator after this point and it would slow down fuzzing.
	// GenActTwo needs to be called to set the appropriate state in the
	// responder machine.
	_, err = responder.GenActTwo()
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Copy data into [ActThreeSize]byte.
	var actThree [brontide.ActThreeSize]byte
	copy(actThree[:], data)

	// Responder receives ActThree, should fail on the MAC check.
	if err := responder.RecvActThree(actThree); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_random_acttwo is a go-fuzz harness for ActTwo in the brontide
// handshake.
func Fuzz_random_acttwo(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActTwoSize {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, _ := getBrontideMachines()

	// Generate ActOne - this isn't sent to the responder because nothing is
	// done with the responder machine and this would slow down fuzzing.
	// GenActOne needs to be called to set the appropriate state in the
	// initiator machine.
	_, err := initiator.GenActOne()
	if err != nil {
		nilAndPanic(initiator, nil, err)
	}

	// Copy data into [ActTwoSize]byte.
	var actTwo [brontide.ActTwoSize]byte
	copy(actTwo[:], data)

	// Initiator receives ActTwo, should fail.
	if err := initiator.RecvActTwo(actTwo); err == nil {
		nilAndPanic(initiator, nil, nil)
	}

	return 1
}

// Fuzz_random_init_decrypt is a go-fuzz harness that decrypts arbitrary data
// with the initiator.
func Fuzz_random_init_decrypt(data []byte) int {
	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Decrypt the encrypted message using ReadMessage w/ initiator machine.
	if _, err := initiator.ReadMessage(r); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_random_init_enc_dec is a go-fuzz harness that tests round-trip
// encryption and decryption between the initiator and the responder.
func Fuzz_random_init_enc_dec(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ initiator machine.
	if err := initiator.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ initiator machine.
	if _, err := initiator.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Decrypt the ciphertext using ReadMessage w/ responder machine.
	plaintext, err := responder.ReadMessage(&b)
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Check that the decrypted message and the original message are equal.
	if !bytes.Equal(data, plaintext) {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_random_init_encrypt is a go-fuzz harness that encrypts arbitrary data
// with the initiator.
func Fuzz_random_init_encrypt(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ initiator machine.
	if err := initiator.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ initiator machine.
	if _, err := initiator.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	return 1
}

// Fuzz_random_resp_decrypt is a go-fuzz harness that decrypts arbitrary data
// with the responder.
func Fuzz_random_resp_decrypt(data []byte) int {
	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Decrypt the encrypted message using ReadMessage w/ responder machine.
	if _, err := responder.ReadMessage(r); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_random_resp_enc_dec is a go-fuzz harness that tests round-trip
// encryption and decryption between the responder and the initiator.
func Fuzz_random_resp_enc_dec(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ responder machine.
	if err := responder.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ responder machine.
	if _, err := responder.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Decrypt the ciphertext using ReadMessage w/ initiator machine.
	plaintext, err := initiator.ReadMessage(&b)
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Check that the decrypted message and the original message are equal.
	if !bytes.Equal(data, plaintext) {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_random_resp_encrypt is a go-fuzz harness that encrypts arbitrary data
// with the responder.
func Fuzz_random_resp_encrypt(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with random keys.
	initiator, responder := getBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ responder machine.
	if err := responder.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ responder machine.
	if _, err := responder.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	return 1
}

// Fuzz_static_actone is a go-fuzz harness for ActOne in the brontide
// handshake.
func Fuzz_static_actone(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActOneSize {
		return 1
	}

	// This will return brontide machines with static keys.
	_, responder := getStaticBrontideMachines()

	// Copy data into [ActOneSize]byte.
	var actOne [brontide.ActOneSize]byte
	copy(actOne[:], data)

	// Responder receives ActOne, should fail.
	if err := responder.RecvActOne(actOne); err == nil {
		nilAndPanic(nil, responder, nil)
	}

	return 1
}

// Fuzz_static_actthree is a go-fuzz harness for ActThree in the brontide
// handshake.
func Fuzz_static_actthree(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActThreeSize {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Generate ActOne and send to the responder.
	actOne, err := initiator.GenActOne()
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Receiving ActOne should succeed, so we panic on error.
	if err := responder.RecvActOne(actOne); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Generate ActTwo - this is not sent to the initiator because nothing is
	// done with the initiator after this point and it would slow down fuzzing.
	// GenActTwo needs to be called to set the appropriate state in the responder
	// machine.
	_, err = responder.GenActTwo()
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Copy data into [ActThreeSize]byte.
	var actThree [brontide.ActThreeSize]byte
	copy(actThree[:], data)

	// Responder receives ActThree, should fail.
	if err := responder.RecvActThree(actThree); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_static_acttwo is a go-fuzz harness for ActTwo in the brontide
// handshake.
func Fuzz_static_acttwo(data []byte) int {
	// Check if data is large enough.
	if len(data) < brontide.ActTwoSize {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, _ := getStaticBrontideMachines()

	// Generate ActOne - this isn't sent to the responder because nothing is
	// done with the responder machine and this would slow down fuzzing.
	// GenActOne needs to be called to set the appropriate state in the initiator
	// machine.
	_, err := initiator.GenActOne()
	if err != nil {
		nilAndPanic(initiator, nil, err)
	}

	// Copy data into [ActTwoSize]byte.
	var actTwo [brontide.ActTwoSize]byte
	copy(actTwo[:], data)

	// Initiator receives ActTwo, should fail.
	if err := initiator.RecvActTwo(actTwo); err == nil {
		nilAndPanic(initiator, nil, nil)
	}

	return 1
}

// Fuzz_static_init_decrypt is a go-fuzz harness that decrypts arbitrary data
// with the initiator.
func Fuzz_static_init_decrypt(data []byte) int {
	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Decrypt the encrypted message using ReadMessage w/ initiator machine.
	if _, err := initiator.ReadMessage(r); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_static_init_enc_dec is a go-fuzz harness that tests round-trip
// encryption and decryption
// between the initiator and the responder.
func Fuzz_static_init_enc_dec(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ initiator machine.
	if err := initiator.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ initiator machine.
	if _, err := initiator.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Decrypt the ciphertext using ReadMessage w/ responder machine.
	plaintext, err := responder.ReadMessage(&b)
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Check that the decrypted message and the original message are equal.
	if !bytes.Equal(data, plaintext) {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_static_init_encrypt is a go-fuzz harness that encrypts arbitrary data
// with the initiator.
func Fuzz_static_init_encrypt(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ initiator machine.
	if err := initiator.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ initiator machine.
	if _, err := initiator.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	return 1
}

// Fuzz_static_resp_decrypt is a go-fuzz harness that decrypts arbitrary data
// with the responder.
func Fuzz_static_resp_decrypt(data []byte) int {
	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Decrypt the encrypted message using ReadMessage w/ responder machine.
	if _, err := responder.ReadMessage(r); err == nil {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_static_resp_enc_dec is a go-fuzz harness that tests round-trip
// encryption and decryption between the responder and the initiator.
func Fuzz_static_resp_enc_dec(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ responder machine.
	if err := responder.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ responder machine.
	if _, err := responder.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Decrypt the ciphertext using ReadMessage w/ initiator machine.
	plaintext, err := initiator.ReadMessage(&b)
	if err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Check that the decrypted message and the original message are equal.
	if !bytes.Equal(data, plaintext) {
		nilAndPanic(initiator, responder, nil)
	}

	return 1
}

// Fuzz_static_resp_encrypt is a go-fuzz harness that encrypts arbitrary data
// with the responder.
func Fuzz_static_resp_encrypt(data []byte) int {
	// Ensure that length of message is not greater than max allowed size.
	if len(data) > math.MaxUint16 {
		return 1
	}

	// This will return brontide machines with static keys.
	initiator, responder := getStaticBrontideMachines()

	// Complete the brontide handshake.
	completeHandshake(initiator, responder)

	var b bytes.Buffer

	// Encrypt the message using WriteMessage w/ responder machine.
	if err := responder.WriteMessage(data); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	// Flush the encrypted message w/ responder machine.
	if _, err := responder.Flush(&b); err != nil {
		nilAndPanic(initiator, responder, err)
	}

	return 1
}
