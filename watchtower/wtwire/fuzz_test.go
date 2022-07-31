package wtwirefuzz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

// prefixWithMsgType takes []byte and adds a wire protocol prefix
// to make the []byte into an actual message to be used in fuzzing.
func prefixWithMsgType(data []byte, prefix wtwire.MessageType) []byte {
	var prefixBytes [2]byte
	binary.BigEndian.PutUint16(prefixBytes[:], uint16(prefix))
	data = append(prefixBytes[:], data...)
	return data
}

// harness performs the actual fuzz testing of the appropriate wire message.
// This function will check that the passed-in message passes wire length checks,
// is a valid message once deserialized, and passes a sequence of serialization
// and deserialization checks. Returns an int that determines whether the input
// is unique or not.
func harness(data []byte, emptyMsg wtwire.Message) int {
	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Make sure byte array length (excluding 2 bytes for message type) is
	// less than max payload size for the wire message. We check this because
	// otherwise `go-fuzz` will keep creating inputs that crash on ReadMessage
	// due to a large message size.
	payloadLen := uint32(len(data)) - 2
	if payloadLen > emptyMsg.MaxPayloadLength(0) {
		// Ignore this input - max payload constraint violated.
		return 1
	}

	msg, err := wtwire.ReadMessage(r, 0)
	if err != nil {
		// go-fuzz generated []byte that cannot be represented as a
		// wire message but we will return 0 so go-fuzz can modify the
		// input.
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := wtwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic.
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := wtwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic.
		panic(err)
	}

	if !reflect.DeepEqual(msg, newMsg) {
		// Deserialized message and original message are not
		// deeply equal.
		panic(fmt.Errorf("deserialized message and original message " +
			"are not deeply equal."))
	}

	// Add this input to the corpus.
	return 1
}

// Fuzz_create_session_reply is used by go-fuzz.
func Fuzz_create_session_reply(data []byte) int {
	// Prefix with MsgCreateSessionReply.
	data = prefixWithMsgType(data, wtwire.MsgCreateSessionReply)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.CreateSessionReply{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_create_session is used by go-fuzz.
func Fuzz_create_session(data []byte) int {
	// Prefix with MsgCreateSession.
	data = prefixWithMsgType(data, wtwire.MsgCreateSession)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.CreateSession{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_delete_session_reply is used by go-fuzz.
func Fuzz_delete_session_reply(data []byte) int {
	// Prefix with MsgDeleteSessionReply.
	data = prefixWithMsgType(data, wtwire.MsgDeleteSessionReply)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.DeleteSessionReply{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_delete_session is used by go-fuzz.
func Fuzz_delete_session(data []byte) int {
	// Prefix with MsgDeleteSession.
	data = prefixWithMsgType(data, wtwire.MsgDeleteSession)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.DeleteSession{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_error is used by go-fuzz.
func Fuzz_error(data []byte) int {
	// Prefix with MsgError.
	data = prefixWithMsgType(data, wtwire.MsgError)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.Error{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_init is used by go-fuzz.
func Fuzz_init(data []byte) int {
	// Prefix with MsgInit.
	data = prefixWithMsgType(data, wtwire.MsgInit)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.Init{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_state_update_reply is used by go-fuzz.
func Fuzz_state_update_reply(data []byte) int {
	// Prefix with MsgStateUpdateReply.
	data = prefixWithMsgType(data, wtwire.MsgStateUpdateReply)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.StateUpdateReply{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}

// Fuzz_state_update is used by go-fuzz.
func Fuzz_state_update(data []byte) int {
	// Prefix with MsgStateUpdate.
	data = prefixWithMsgType(data, wtwire.MsgStateUpdate)

	// Create an empty message so that the FuzzHarness func can check if the
	// max payload constraint is violated.
	emptyMsg := wtwire.StateUpdate{}

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data, &emptyMsg)
}
