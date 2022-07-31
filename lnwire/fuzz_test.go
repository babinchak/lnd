package lnwirefuzz

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"reflect"

	"github.com/lightningnetwork/lnd/lnwire"
)

// prefixWithMsgType takes []byte and adds a wire protocol prefix
// to make the []byte into an actual message to be used in fuzzing.
func prefixWithMsgType(data []byte, prefix lnwire.MessageType) []byte {
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
func harness(data []byte) int {
	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Check that the created message is not greater than the maximum
	// message size.
	if len(data) > lnwire.MaxSliceLength {
		return 1
	}

	msg, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := lnwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic
		panic(err)
	}

	if !reflect.DeepEqual(msg, newMsg) {
		// Deserialized message and original message are not deeply equal.
		panic("original message and deserialized message are not deeply equal")
	}

	return 1
}

// Fuzz_accept_channel is used by go-fuzz.
func Fuzz_accept_channel(data []byte) int {
	// Prefix with MsgAcceptChannel.
	data = prefixWithMsgType(data, lnwire.MsgAcceptChannel)

	// We have to do this here instead of in fuzz.Harness so that
	// reflect.DeepEqual isn't called. Because of the UpfrontShutdownScript
	// encoding, the first message and second message aren't deeply equal since
	// the first has a nil slice and the other has an empty slice.

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Make sure byte array length (excluding 2 bytes for message type) is
	// less than max payload size for the wire message.
	payloadLen := uint32(len(data)) - 2
	if payloadLen > lnwire.MaxMsgBody {
		return 1
	}

	msg, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		// go-fuzz generated []byte that cannot be represented as a
		// wire message but we will return 0 so go-fuzz can modify the
		// input.
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := lnwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic
		panic(err)
	}

	// Now compare every field instead of using reflect.DeepEqual.
	// For UpfrontShutdownScript, we only compare bytes. This probably takes
	// up more branches than necessary, but that's fine for now.
	var shouldPanic bool
	first := msg.(*lnwire.AcceptChannel)
	second := newMsg.(*lnwire.AcceptChannel)

	if !bytes.Equal(first.PendingChannelID[:], second.PendingChannelID[:]) {
		shouldPanic = true
	}

	if first.DustLimit != second.DustLimit {
		shouldPanic = true
	}

	if first.MaxValueInFlight != second.MaxValueInFlight {
		shouldPanic = true
	}

	if first.ChannelReserve != second.ChannelReserve {
		shouldPanic = true
	}

	if first.HtlcMinimum != second.HtlcMinimum {
		shouldPanic = true
	}

	if first.MinAcceptDepth != second.MinAcceptDepth {
		shouldPanic = true
	}

	if first.CsvDelay != second.CsvDelay {
		shouldPanic = true
	}

	if first.MaxAcceptedHTLCs != second.MaxAcceptedHTLCs {
		shouldPanic = true
	}

	if !first.FundingKey.IsEqual(second.FundingKey) {
		shouldPanic = true
	}

	if !first.RevocationPoint.IsEqual(second.RevocationPoint) {
		shouldPanic = true
	}

	if !first.PaymentPoint.IsEqual(second.PaymentPoint) {
		shouldPanic = true
	}

	if !first.DelayedPaymentPoint.IsEqual(second.DelayedPaymentPoint) {
		shouldPanic = true
	}

	if !first.HtlcPoint.IsEqual(second.HtlcPoint) {
		shouldPanic = true
	}

	if !first.FirstCommitmentPoint.IsEqual(second.FirstCommitmentPoint) {
		shouldPanic = true
	}

	if !bytes.Equal(first.UpfrontShutdownScript, second.UpfrontShutdownScript) {
		shouldPanic = true
	}

	if shouldPanic {
		panic("original message and deserialized message are not equal")
	}

	// Add this input to the corpus.
	return 1
}

// Fuzz_announce_signatures is used by go-fuzz.
func Fuzz_announce_signatures(data []byte) int {
	// Prefix with MsgAnnounceSignatures.
	data = prefixWithMsgType(data, lnwire.MsgAnnounceSignatures)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_channel_announcement is used by go-fuzz.
func Fuzz_channel_announcement(data []byte) int {
	// Prefix with MsgChannelAnnouncement.
	data = prefixWithMsgType(data, lnwire.MsgChannelAnnouncement)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_channel_reestablish is used by go-fuzz.
func Fuzz_channel_reestablish(data []byte) int {
	// Prefix with MsgChannelReestablish.
	data = prefixWithMsgType(data, lnwire.MsgChannelReestablish)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_channel_update is used by go-fuzz.
func Fuzz_channel_update(data []byte) int {
	// Prefix with MsgChannelUpdate.
	data = prefixWithMsgType(data, lnwire.MsgChannelUpdate)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_closing_signed is used by go-fuzz.
func Fuzz_closing_signed(data []byte) int {
	// Prefix with MsgClosingSigned.
	data = prefixWithMsgType(data, lnwire.MsgClosingSigned)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_commit_sig is used by go-fuzz.
func Fuzz_commit_sig(data []byte) int {
	// Prefix with MsgCommitSig.
	data = prefixWithMsgType(data, lnwire.MsgCommitSig)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_error is used by go-fuzz.
func Fuzz_error(data []byte) int {
	// Prefix with MsgError.
	data = prefixWithMsgType(data, lnwire.MsgError)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_funding_created is used by go-fuzz.
func Fuzz_funding_created(data []byte) int {
	// Prefix with MsgFundingCreated.
	data = prefixWithMsgType(data, lnwire.MsgFundingCreated)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_funding_locked is used by go-fuzz.
func Fuzz_funding_locked(data []byte) int {
	// Prefix with MsgFundingLocked.
	data = prefixWithMsgType(data, lnwire.MsgFundingLocked)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_funding_signed is used by go-fuzz.
func Fuzz_funding_signed(data []byte) int {
	// Prefix with MsgFundingSigned.
	prefixWithMsgType(data, lnwire.MsgFundingSigned)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_gossip_timestamp_range is used by go-fuzz.
func Fuzz_gossip_timestamp_range(data []byte) int {
	// Prefix with MsgGossipTimestampRange.
	data = prefixWithMsgType(data, lnwire.MsgGossipTimestampRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_init is used by go-fuzz.
func Fuzz_init(data []byte) int {
	// Prefix with MsgInit.
	data = prefixWithMsgType(data, lnwire.MsgInit)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_node_announcement is used by go-fuzz.
func Fuzz_node_announcement(data []byte) int {
	// Prefix with MsgNodeAnnouncement.
	data = prefixWithMsgType(data, lnwire.MsgNodeAnnouncement)

	// We have to do this here instead of in fuzz.Harness so that
	// reflect.DeepEqual isn't called. Address (de)serialization messes up
	// the fuzzing assertions.

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Make sure byte array length (excluding 2 bytes for message type) is
	// less than max payload size for the wire message.
	payloadLen := uint32(len(data)) - 2
	if payloadLen > lnwire.MaxMsgBody {
		return 1
	}

	msg, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := lnwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic
		panic(err)
	}

	// Now compare every field instead of using reflect.DeepEqual for the
	// Addresses field.
	var shouldPanic bool
	first := msg.(*lnwire.NodeAnnouncement)
	second := newMsg.(*lnwire.NodeAnnouncement)
	if !bytes.Equal(first.Signature[:], second.Signature[:]) {
		shouldPanic = true
	}

	if !reflect.DeepEqual(first.Features, second.Features) {
		shouldPanic = true
	}

	if first.Timestamp != second.Timestamp {
		shouldPanic = true
	}

	if !bytes.Equal(first.NodeID[:], second.NodeID[:]) {
		shouldPanic = true
	}

	if !reflect.DeepEqual(first.RGBColor, second.RGBColor) {
		shouldPanic = true
	}

	if !bytes.Equal(first.Alias[:], second.Alias[:]) {
		shouldPanic = true
	}

	if len(first.Addresses) != len(second.Addresses) {
		shouldPanic = true
	}

	for i := range first.Addresses {
		if first.Addresses[i].String() != second.Addresses[i].String() {
			shouldPanic = true
			break
		}
	}

	if !reflect.DeepEqual(first.ExtraOpaqueData, second.ExtraOpaqueData) {
		shouldPanic = true
	}

	if shouldPanic {
		panic("original message and deserialized message are not equal")
	}

	// Add this input to the corpus.
	return 1
}

// Fuzz_open_channel is used by go-fuzz.
func Fuzz_open_channel(data []byte) int {
	// Prefix with MsgOpenChannel.
	data = prefixWithMsgType(data, lnwire.MsgOpenChannel)

	// We have to do this here instead of in fuzz.Harness so that
	// reflect.DeepEqual isn't called. Because of the UpfrontShutdownScript
	// encoding, the first message and second message aren't deeply equal since
	// the first has a nil slice and the other has an empty slice.

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Make sure byte array length (excluding 2 bytes for message type) is
	// less than max payload size for the wire message.
	payloadLen := uint32(len(data)) - 2
	if payloadLen > lnwire.MaxMsgBody {
		return 1
	}

	msg, err := lnwire.ReadMessage(r, 0)
	if err != nil {
		return 1
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	if _, err := lnwire.WriteMessage(&b, msg, 0); err != nil {
		// Could not serialize message into bytes buffer, panic
		panic(err)
	}

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := lnwire.ReadMessage(&b, 0)
	if err != nil {
		// Could not deserialize message from bytes buffer, panic
		panic(err)
	}

	// Now compare every field instead of using reflect.DeepEqual.
	// For UpfrontShutdownScript, we only compare bytes. This probably takes
	// up more branches than necessary, but that's fine for now.
	var shouldPanic bool
	first := msg.(*lnwire.OpenChannel)
	second := newMsg.(*lnwire.OpenChannel)

	if !first.ChainHash.IsEqual(&second.ChainHash) {
		shouldPanic = true
	}

	if !bytes.Equal(first.PendingChannelID[:], second.PendingChannelID[:]) {
		shouldPanic = true
	}

	if first.FundingAmount != second.FundingAmount {
		shouldPanic = true
	}

	if first.PushAmount != second.PushAmount {
		shouldPanic = true
	}

	if first.DustLimit != second.DustLimit {
		shouldPanic = true
	}

	if first.MaxValueInFlight != second.MaxValueInFlight {
		shouldPanic = true
	}

	if first.ChannelReserve != second.ChannelReserve {
		shouldPanic = true
	}

	if first.HtlcMinimum != second.HtlcMinimum {
		shouldPanic = true
	}

	if first.FeePerKiloWeight != second.FeePerKiloWeight {
		shouldPanic = true
	}

	if first.CsvDelay != second.CsvDelay {
		shouldPanic = true
	}

	if first.MaxAcceptedHTLCs != second.MaxAcceptedHTLCs {
		shouldPanic = true
	}

	if !first.FundingKey.IsEqual(second.FundingKey) {
		shouldPanic = true
	}

	if !first.RevocationPoint.IsEqual(second.RevocationPoint) {
		shouldPanic = true
	}

	if !first.PaymentPoint.IsEqual(second.PaymentPoint) {
		shouldPanic = true
	}

	if !first.DelayedPaymentPoint.IsEqual(second.DelayedPaymentPoint) {
		shouldPanic = true
	}

	if !first.HtlcPoint.IsEqual(second.HtlcPoint) {
		shouldPanic = true
	}

	if !first.FirstCommitmentPoint.IsEqual(second.FirstCommitmentPoint) {
		shouldPanic = true
	}

	if first.ChannelFlags != second.ChannelFlags {
		shouldPanic = true
	}

	if !bytes.Equal(first.UpfrontShutdownScript, second.UpfrontShutdownScript) {
		shouldPanic = true
	}

	if shouldPanic {
		panic("original message and deserialized message are not equal")
	}

	// Add this input to the corpus.
	return 1
}

// Fuzz_ping is used by go-fuzz.
func Fuzz_ping(data []byte) int {
	// Prefix with MsgPing.
	data = prefixWithMsgType(data, lnwire.MsgPing)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_pong is used by go-fuzz.
func Fuzz_pong(data []byte) int {
	// Prefix with MsgPong.
	data = prefixWithMsgType(data, lnwire.MsgPong)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_query_channel_range is used by go-fuzz.
func Fuzz_query_channel_range(data []byte) int {
	// Prefix with MsgQueryChannelRange.
	data = prefixWithMsgType(data, lnwire.MsgQueryChannelRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_query_short_chan_ids_zlib is used by go-fuzz.
func Fuzz_query_short_chan_ids_zlib(data []byte) int {

	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	_, err := zlibWriter.Write(data)
	if err != nil {
		// Zlib bug?
		panic(err)
	}

	if err := zlibWriter.Close(); err != nil {
		// Zlib bug?
		panic(err)
	}

	compressedPayload := buf.Bytes()

	chainhash := []byte("00000000000000000000000000000000")
	numBytesInBody := len(compressedPayload) + 1
	zlibByte := []byte("\x01")

	bodyBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

	payload := append(chainhash, bodyBytes...)
	payload = append(payload, zlibByte...)
	payload = append(payload, compressedPayload...)

	// Prefix with MsgQueryShortChanIDs.
	payload = prefixWithMsgType(payload, lnwire.MsgQueryShortChanIDs)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(payload)
}

// Fuzz_query_short_chan_ids is used by go-fuzz.
func Fuzz_query_short_chan_ids(data []byte) int {
	// Prefix with MsgQueryShortChanIDs.
	data = prefixWithMsgType(data, lnwire.MsgQueryShortChanIDs)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_reply_channel_range_zlib is used by go-fuzz.
func Fuzz_reply_channel_range_zlib(data []byte) int {

	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	_, err := zlibWriter.Write(data)
	if err != nil {
		// Zlib bug?
		panic(err)
	}

	if err := zlibWriter.Close(); err != nil {
		// Zlib bug?
		panic(err)
	}

	compressedPayload := buf.Bytes()

	// Initialize some []byte vars which will prefix our payload
	chainhash := []byte("00000000000000000000000000000000")
	firstBlockHeight := []byte("\x00\x00\x00\x00")
	numBlocks := []byte("\x00\x00\x00\x00")
	completeByte := []byte("\x00")

	numBytesInBody := len(compressedPayload) + 1
	zlibByte := []byte("\x01")

	bodyBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

	payload := append(chainhash, firstBlockHeight...)
	payload = append(payload, numBlocks...)
	payload = append(payload, completeByte...)
	payload = append(payload, bodyBytes...)
	payload = append(payload, zlibByte...)
	payload = append(payload, compressedPayload...)

	// Prefix with MsgReplyChannelRange.
	payload = prefixWithMsgType(payload, lnwire.MsgReplyChannelRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(payload)
}

// Fuzz_reply_channel_range is used by go-fuzz.
func Fuzz_reply_channel_range(data []byte) int {
	// Prefix with MsgReplyChannelRange.
	data = prefixWithMsgType(data, lnwire.MsgReplyChannelRange)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_reply_short_chan_ids_end is used by go-fuzz.
func Fuzz_reply_short_chan_ids_end(data []byte) int {
	// Prefix with MsgReplyShortChanIDsEnd.
	data = prefixWithMsgType(data, lnwire.MsgReplyShortChanIDsEnd)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_revoke_and_ack is used by go-fuzz.
func Fuzz_revoke_and_ack(data []byte) int {
	// Prefix with MsgRevokeAndAck.
	data = prefixWithMsgType(data, lnwire.MsgRevokeAndAck)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_shutdown is used by go-fuzz.
func Fuzz_shutdown(data []byte) int {
	// Prefix with MsgShutdown.
	data = prefixWithMsgType(data, lnwire.MsgShutdown)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_update_add_htlc is used by go-fuzz.
func Fuzz_update_add_htlc(data []byte) int {
	// Prefix with MsgUpdateAddHTLC.
	data = prefixWithMsgType(data, lnwire.MsgUpdateAddHTLC)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_update_fail_htlc is used by go-fuzz.
func Fuzz_update_fail_htlc(data []byte) int {
	// Prefix with MsgUpdateFailHTLC.
	data = prefixWithMsgType(data, lnwire.MsgUpdateFailHTLC)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_update_fail_malformed_htlc is used by go-fuzz.
func Fuzz_update_fail_malformed_htlc(data []byte) int {
	// Prefix with MsgUpdateFailMalformedHTLC.
	data = prefixWithMsgType(data, lnwire.MsgUpdateFailMalformedHTLC)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_update_fee is used by go-fuzz.
func Fuzz_update_fee(data []byte) int {
	// Prefix with MsgUpdateFee.
	data = prefixWithMsgType(data, lnwire.MsgUpdateFee)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}

// Fuzz_update_fulfill_htlc is used by go-fuzz.
func Fuzz_update_fulfill_htlc(data []byte) int {
	// Prefix with MsgUpdateFulfillHTLC.
	data = prefixWithMsgType(data, lnwire.MsgUpdateFulfillHTLC)

	// Pass the message into our general fuzz harness for wire messages!
	return harness(data)
}
