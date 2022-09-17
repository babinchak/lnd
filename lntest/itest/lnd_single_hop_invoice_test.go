package itest

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
)

func testSingleHopInvoice(net *lntest.NetworkHarness, t *harnessTest) {
	// This test has been modified to complete the following exercise, and
	// not meant to be merged into master: In
	// https://github.com/lightningnetwork/lnd/blob/6d661334599ffa2a409ad6b0942328f9fd213d09/lntest/itest/lnd_single_hop_invoice_test.go#L24-L33
	// Alice sends payment to Bob. Add a new node (Carol), open a channel
	// from Bob to Carol and then send a payment from Alice to Bob to Carol.
	// (hint: `make itest icase=single_hop_invoice log=stdout` runs that
	// specific test, otherwise you’ll be running the full test suite for
	// bitcoind/neutrino/btcd) Create a gist and please include the
	// modifications you made and an output of the test you created.

	ctxb := context.Background()

	// Open a channel with 100k satoshis between Alice and Bob with Alice
	// being the sole funder of the channel.
	chanAmt := btcutil.Amount(100000)
	chanPointAlice := openChannelAndAssert(
		t, net, net.Alice, net.Bob,
		lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Create Carol node
	carol := net.NewNode(t.t, "Carol", nil)
	defer shutdownAndAssert(net, t, carol)

	// Open channel between Bob and Carol also with 100k satoshis
	net.ConnectNodes(t.t, net.Bob, carol)
	chanPointBob := openChannelAndAssert(
		t, net, net.Bob, carol, lntest.OpenChannelParams{
			Amt: chanAmt,
		},
	)

	// Now that the channel is open, create an invoice for Carol which
	// expects a payment of 1000 satoshis from Alice paid via a particular
	// preimage.
	const paymentAmt = 1000
	preimage := bytes.Repeat([]byte("A"), 32)
	invoice := &lnrpc.Invoice{
		Memo:      "testing",
		RPreimage: preimage,
		Value:     paymentAmt,
	}
	invoiceResp, err := carol.AddInvoice(ctxb, invoice)
	if err != nil {
		t.Fatalf("unable to add invoice: %v", err)
	}

	// Wait for all nodes to have seen all channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol}
	nodeNames := []string{"Alice", "Bob", "Carol"}
	chans := []*lnrpc.ChannelPoint{chanPointAlice, chanPointBob}
	for _, chanPoint := range chans {
		for i, node := range nodes {
			err = node.WaitForNetworkChannelOpen(chanPoint)
			if err != nil {
				t.Fatalf("%s didn't advertise channel before"+
					"timeout: %v", nodeNames[i], err)
			}
		}
	}

	// With the invoice for Carol added, send a payment towards Alice paying
	// to the above generated invoice.
	resp := sendAndAssertSuccess(
		t, net.Alice, &routerrpc.SendPaymentRequest{
			PaymentRequest: invoiceResp.PaymentRequest,
			TimeoutSeconds: 60,
			FeeLimitMsat:   noFeeLimitMsat,
		},
	)
	if hex.EncodeToString(preimage) != resp.PaymentPreimage {
		t.Fatalf("preimage mismatch: expected %v, got %v", preimage,
			resp.PaymentPreimage)
	}

	// Carols's invoice should now be found and marked as settled.
	payHash := &lnrpc.PaymentHash{
		RHash: invoiceResp.RHash,
	}
	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	dbInvoice, err := carol.LookupInvoice(ctxt, payHash)
	if err != nil {
		t.Fatalf("unable to lookup invoice: %v", err)
	}
	if !dbInvoice.Settled { // nolint:staticcheck
		t.Fatalf("bob's invoice should be marked as settled: %v",
			spew.Sdump(dbInvoice))
	}

	// With the payment completed all balance related stats should be
	// properly updated.
	aliceChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointAlice)
	aliceFundPoint := wire.OutPoint{
		Hash:  *aliceChanTXID,
		Index: chanPointAlice.OutputIndex,
	}
	const baseFee = 1
	assertAmountPaid(t, "Alice -> Bob", net.Alice,
		aliceFundPoint, paymentAmt+baseFee, 0)

	bobChanTXID, err := lnrpc.GetChanPointFundingTxid(chanPointBob)
	bobFundPoint := wire.OutPoint{
		Hash:  *bobChanTXID,
		Index: chanPointBob.OutputIndex,
	}
	assertAmountPaid(t, "Bob -> Carol", net.Bob,
		bobFundPoint, paymentAmt, 0)

	// Delete the other parts of the original test

	closeChannelAndAssert(t, net, net.Alice, chanPointAlice, false)
	closeChannelAndAssert(t, net, net.Bob, chanPointBob, false)
}
