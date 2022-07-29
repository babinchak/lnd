package brontide

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
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
	initEphemeral = EphemeralGenerator(func() (*btcec.PrivateKey, error) {
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
	respEphemeral = EphemeralGenerator(func() (*btcec.PrivateKey, error) {
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
func completeHandshake(initiator, responder *Machine, t *testing.T) {
	if err := handshake(initiator, responder); err != nil {
		nilAndPanic(initiator, responder, err, t)
	}
}

// handshake actually completes the brontide handshake and bubbles up
// an error to the calling function.
func handshake(initiator, responder *Machine) error {
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
func nilAndPanic(initiator, responder *Machine, err error, t *testing.T) {
	t.Fatalf("error: %v, initiator: %v, responder: %v", err,
		spew.Sdump(initiator), spew.Sdump(responder))
}

// getBrontideMachines returns two brontide machines that use random keys
// everywhere.
func getBrontideMachines() (*Machine, *Machine) {
	initPriv, _ := btcec.NewPrivateKey()
	respPriv, _ := btcec.NewPrivateKey()
	respPub := (*btcec.PublicKey)(respPriv.PubKey())

	initPrivECDH := &keychain.PrivKeyECDH{PrivKey: initPriv}
	respPrivECDH := &keychain.PrivKeyECDH{PrivKey: respPriv}

	initiator := NewBrontideMachine(true, initPrivECDH, respPub)
	responder := NewBrontideMachine(false, respPrivECDH, nil)

	return initiator, responder
}

// getStaticBrontideMachines returns two brontide machines that use static keys
// everywhere.
func getStaticBrontideMachines() (*Machine, *Machine) {
	initPriv, _ := btcec.PrivKeyFromBytes(initBytes)
	respPriv, respPub := btcec.PrivKeyFromBytes(respBytes)

	initPrivECDH := &keychain.PrivKeyECDH{PrivKey: initPriv}
	respPrivECDH := &keychain.PrivKeyECDH{PrivKey: respPriv}

	initiator := NewBrontideMachine(
		true, initPrivECDH, respPub, initEphemeral,
	)
	responder := NewBrontideMachine(
		false, respPrivECDH, nil, respEphemeral,
	)

	return initiator, responder
}

func Fuzz_random_actone(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActOneSize {
			return
		}

		// This will return brontide machines with random keys.
		_, responder := getBrontideMachines()

		// Copy data into [ActOneSize]byte.
		var actOne [ActOneSize]byte
		copy(actOne[:], data)

		// Responder receives ActOne, should fail on the MAC check.
		if err := responder.RecvActOne(actOne); err == nil {
			nilAndPanic(nil, responder, nil, t)
		}
	})
}

func Fuzz_random_actthree(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActThreeSize {
			return
		}

		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Generate ActOne and send to the responder.
		actOne, err := initiator.GenActOne()
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Receiving ActOne should succeed, so we panic on error.
		if err := responder.RecvActOne(actOne); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Generate ActTwo - this is not sent to the initiator because nothing is
		// done with the initiator after this point and it would slow down fuzzing.
		// GenActTwo needs to be called to set the appropriate state in the
		// responder machine.
		_, err = responder.GenActTwo()
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Copy data into [ActThreeSize]byte.
		var actThree [ActThreeSize]byte
		copy(actThree[:], data)

		// Responder receives ActThree, should fail on the MAC check.
		if err := responder.RecvActThree(actThree); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_random_acttwo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActTwoSize {
			return
		}

		// This will return brontide machines with random keys.
		initiator, _ := getBrontideMachines()

		// Generate ActOne - this isn't sent to the responder because nothing is
		// done with the responder machine and this would slow down fuzzing.
		// GenActOne needs to be called to set the appropriate state in the
		// initiator machine.
		_, err := initiator.GenActOne()
		if err != nil {
			nilAndPanic(initiator, nil, err, t)
		}

		// Copy data into [ActTwoSize]byte.
		var actTwo [ActTwoSize]byte
		copy(actTwo[:], data)

		// Initiator receives ActTwo, should fail.
		if err := initiator.RecvActTwo(actTwo); err == nil {
			nilAndPanic(initiator, nil, nil, t)
		}

	})
}

func Fuzz_random_init_decrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Decrypt the encrypted message using ReadMessage w/ initiator machine.
		if _, err := initiator.ReadMessage(r); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_random_init_enc_dec(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ initiator machine.
		if err := initiator.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ initiator machine.
		if _, err := initiator.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Decrypt the ciphertext using ReadMessage w/ responder machine.
		plaintext, err := responder.ReadMessage(&b)
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Check that the decrypted message and the original message are equal.
		if !bytes.Equal(data, plaintext) {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_random_init_encrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ initiator machine.
		if err := initiator.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ initiator machine.
		if _, err := initiator.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

	})
}

func Fuzz_random_resp_decrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Decrypt the encrypted message using ReadMessage w/ responder machine.
		if _, err := responder.ReadMessage(r); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_resp_enc_dec(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ responder machine.
		if err := responder.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ responder machine.
		if _, err := responder.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Decrypt the ciphertext using ReadMessage w/ initiator machine.
		plaintext, err := initiator.ReadMessage(&b)
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Check that the decrypted message and the original message are equal.
		if !bytes.Equal(data, plaintext) {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_resp_encrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with random keys.
		initiator, responder := getBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ responder machine.
		if err := responder.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ responder machine.
		if _, err := responder.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

	})
}

func Fuzz_static_actone(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActOneSize {
			return
		}

		// This will return brontide machines with static keys.
		_, responder := getStaticBrontideMachines()

		// Copy data into [ActOneSize]byte.
		var actOne [ActOneSize]byte
		copy(actOne[:], data)

		// Responder receives ActOne, should fail.
		if err := responder.RecvActOne(actOne); err == nil {
			nilAndPanic(nil, responder, nil, t)
		}

	})
}

func Fuzz_static_actthree(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActThreeSize {
			return
		}

		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Generate ActOne and send to the responder.
		actOne, err := initiator.GenActOne()
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Receiving ActOne should succeed, so we panic on error.
		if err := responder.RecvActOne(actOne); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Generate ActTwo - this is not sent to the initiator because nothing is
		// done with the initiator after this point and it would slow down fuzzing.
		// GenActTwo needs to be called to set the appropriate state in the responder
		// machine.
		_, err = responder.GenActTwo()
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Copy data into [ActThreeSize]byte.
		var actThree [ActThreeSize]byte
		copy(actThree[:], data)

		// Responder receives ActThree, should fail.
		if err := responder.RecvActThree(actThree); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_static_acttwo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Check if data is large enough.
		if len(data) < ActTwoSize {
			return
		}

		// This will return brontide machines with static keys.
		initiator, _ := getStaticBrontideMachines()

		// Generate ActOne - this isn't sent to the responder because nothing is
		// done with the responder machine and this would slow down fuzzing.
		// GenActOne needs to be called to set the appropriate state in the initiator
		// machine.
		_, err := initiator.GenActOne()
		if err != nil {
			nilAndPanic(initiator, nil, err, t)
		}

		// Copy data into [ActTwoSize]byte.
		var actTwo [ActTwoSize]byte
		copy(actTwo[:], data)

		// Initiator receives ActTwo, should fail.
		if err := initiator.RecvActTwo(actTwo); err == nil {
			nilAndPanic(initiator, nil, nil, t)
		}

	})
}

func Fuzz_static_init_decrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Decrypt the encrypted message using ReadMessage w/ initiator machine.
		if _, err := initiator.ReadMessage(r); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_init_enc_dec(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ initiator machine.
		if err := initiator.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ initiator machine.
		if _, err := initiator.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Decrypt the ciphertext using ReadMessage w/ responder machine.
		plaintext, err := responder.ReadMessage(&b)
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Check that the decrypted message and the original message are equal.
		if !bytes.Equal(data, plaintext) {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_static_init_encrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ initiator machine.
		if err := initiator.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ initiator machine.
		if _, err := initiator.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

	})
}

func Fuzz_static_resp_decrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Decrypt the encrypted message using ReadMessage w/ responder machine.
		if _, err := responder.ReadMessage(r); err == nil {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_static_resp_enc_dec(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ responder machine.
		if err := responder.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ responder machine.
		if _, err := responder.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Decrypt the ciphertext using ReadMessage w/ initiator machine.
		plaintext, err := initiator.ReadMessage(&b)
		if err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Check that the decrypted message and the original message are equal.
		if !bytes.Equal(data, plaintext) {
			nilAndPanic(initiator, responder, nil, t)
		}

	})
}

func Fuzz_static_resp_encrypt(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that length of message is not greater than max allowed size.
		if len(data) > math.MaxUint16 {
			return
		}

		// This will return brontide machines with static keys.
		initiator, responder := getStaticBrontideMachines()

		// Complete the brontide handshake.
		completeHandshake(initiator, responder, t)

		var b bytes.Buffer

		// Encrypt the message using WriteMessage w/ responder machine.
		if err := responder.WriteMessage(data); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}

		// Flush the encrypted message w/ responder machine.
		if _, err := responder.Flush(&b); err != nil {
			nilAndPanic(initiator, responder, err, t)
		}
	})
}
