/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	s256k1 "github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func (parties parties) init(senders []Sender) {
	for i, p := range parties {
		p.Init(parties.numericIDs(), len(parties)-1, senders[i])
	}
}

func (parties parties) setShareData(shareData [][]byte) {
	for i, p := range parties {
		p.SetShareData(shareData[i])
	}
}

func (parties parties) sign(msg []byte) ([]byte, error) {
	var lock sync.Mutex
	var sigs [][]byte
	var threadSafeError atomic.Value

	var wg sync.WaitGroup
	wg.Add(len(parties))

	for _, p := range parties {
		go func(p *party) {
			defer wg.Done()
			sig, err := p.Sign(context.Background(), msg)
			if err != nil {
				threadSafeError.Store(err.Error())
				return
			}

			lock.Lock()
			sigs = append(sigs, sig)
			lock.Unlock()
		}(p)
	}

	wg.Wait()

	err := threadSafeError.Load()
	if err != nil {
		return nil, fmt.Errorf(err.(string))
	}

	return sigs[0], nil
}

func (parties parties) keygen() ([][]byte, error) {
	var lock sync.Mutex
	shares := make([][]byte, len(parties))
	var threadSafeError atomic.Value

	var wg sync.WaitGroup
	wg.Add(len(parties))

	for i, p := range parties {
		go func(p *party, i int) {
			defer wg.Done()
			share, err := p.KeyGen(context.Background())
			if err != nil {
				threadSafeError.Store(err.Error())
				return
			}

			lock.Lock()
			shares[i] = share
			lock.Unlock()
		}(p, i)
	}

	wg.Wait()

	err := threadSafeError.Load()
	if err != nil {
		return nil, fmt.Errorf(err.(string))
	}

	return shares, nil
}

func (parties parties) Mapping() map[string]*tss.PartyID {
	partyIDMap := make(map[string]*tss.PartyID)
	for _, id := range parties {
		partyIDMap[id.id.Id] = id.id
	}
	return partyIDMap
}

func TestTSS(t *testing.T) {
	curve := s256k1.S256()

	t.Run(curve.Params().Name, func(t *testing.T) {
		pA := NewParty(1, curve, logger("pA", t.Name()))
		pB := NewParty(2, curve, logger("pB", t.Name()))
		pC := NewParty(3, curve, logger("pC", t.Name()))

		cid := big.NewInt(1337)

		t.Logf("Created parties")

		parties := parties{pA, pB, pC}
		parties.init(senders(parties))

		t.Logf("Running DKG")

		t1 := time.Now()
		shares, err := parties.keygen()
		assert.NoError(t, err)
		t.Logf("DKG elapsed %s", time.Since(t1))

		parties.init(senders(parties))

		parties.setShareData(shares)
		t.Logf("Signing")

		addr := common.HexToAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID: cid,
			//ChainID:    big.NewInt(1),
			Nonce:      0,
			To:         &addr,
			Gas:        0x5208,
			GasTipCap:  big.NewInt(0x4de4fb81),
			GasFeeCap:  big.NewInt(0x4a76c17a4),
			Value:      big.NewInt(0x0),
			Data:       []byte{},
			AccessList: types.AccessList{},
		})

		//hashh := signer.Hash(tx).Hex()
		//fmt.Println(hashh)
		//fmt.Println(tx.Hash().Hex())

		//keccakRlpTrx := []byte(hashh)
		keccakRlpTrx := tx.Hash().Bytes()

		t.Logf("Signing message")
		t1 = time.Now()
		sig, err := parties.sign(keccakRlpTrx)
		assert.NoError(t, err)
		t.Logf("Signing completed in %v", time.Since(t1))

		// sigSet := make(map[string]struct{})
		// for _, s := range sigs {
		// 	sigSet[string(s)] = struct{}{}
		// }
		// assert.Len(t, sigSet, 1)

		pk, err := parties[0].TPubKey()
		assert.NoError(t, err)

		// sigHex := hex.EncodeToString(sig)
		pkBytes := []byte{04}
		pkBytes = append(pkBytes, pk.X.Bytes()...)
		pkBytes = append(pkBytes, pk.Y.Bytes()...)

		fmt.Println(len(pkBytes))
		fmt.Println(len(keccakRlpTrx))
		fmt.Println(len(sig))
		// fmt.Println(crypto.VerifySignature(pkBytes, keccakRlpTrx, sig))

		// assert.True(t, crypto.VerifySignature(pkBytes, keccakRlpTrx, sig))
		recPk, err := crypto.Ecrecover(keccakRlpTrx, sig)

		assert.NoError(t, err)

		assert.Equal(t, recPk, pkBytes)

		fmt.Println(common.BytesToAddress(pkBytes).Hex())
		fmt.Println(common.BytesToAddress(recPk).Hex())

		signer := types.NewLondonSigner(cid)
		signature, err := tx.WithSignature(signer, sig)
		assert.NoError(t, err)

		sender, err := types.Sender(signer, signature)
		fmt.Println(sender.Hex())

		client, _ := ethclient.Dial("http://127.0.0.1:8545")
		err = client.SendTransaction(context.Background(), signature)
		fmt.Println(err)
		assert.NoError(t, err)
	})
}

func verifySignature(pk *ecdsa.PublicKey, msg []byte, sig []byte) bool {
	// convert pk to s256k1.PublicKey
	xFieldVal, yFieldVal := new(secp256k1.FieldVal), new(secp256k1.FieldVal)
	xFieldVal.SetByteSlice(pk.X.Bytes())
	yFieldVal.SetByteSlice(pk.Y.Bytes())
	btcecPubKey := btcec.NewPublicKey(xFieldVal, yFieldVal)

	signature, err := btcecdsa.ParseDERSignature(sig)
	if err != nil {
		return false
	}

	pubBytes := append(pk.X.Bytes(), pk.Y.Bytes()...)
	pubHex := hex.EncodeToString(pubBytes)
	asdf := common.BytesToAddress(common.FromHex(pubHex))
	fmt.Println("Public key in hex:", asdf)

	addr, err := crypto.Ecrecover(msg, append(pk.X.Bytes(), append(pk.Y.Bytes(), 0)...))
	fmt.Println("recover", common.BytesToAddress(addr), err)

	return signature.Verify(msg, btcecPubKey)
}

func senders(parties parties) []Sender {
	var senders []Sender
	for _, src := range parties {
		src := src
		sender := func(msgBytes []byte, broadcast bool, to uint16) {
			messageSource := uint16(big.NewInt(0).SetBytes(src.id.Key).Uint64())
			if broadcast {
				for _, dst := range parties {
					if dst.id == src.id {
						continue
					}
					dst.OnMsg(msgBytes, messageSource, broadcast)
				}
			} else {
				for _, dst := range parties {
					if to != uint16(big.NewInt(0).SetBytes(dst.id.Key).Uint64()) {
						continue
					}
					dst.OnMsg(msgBytes, messageSource, broadcast)
				}
			}
		}
		senders = append(senders, sender)
	}
	return senders
}

func logger(id string, testName string) Logger {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	logger = logger.With(zap.String("t", testName)).With(zap.String("id", id))
	return logger.Sugar()
}
