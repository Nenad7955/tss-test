/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	common2 "github.com/bnb-chain/tss-lib/v2/common"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/tss"
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

func (parties parties) sign(msg []byte) ([][]byte, *common2.SignatureData, error) {
	var lock sync.Mutex
	var sigs [][]byte
	var threadSafeError atomic.Value

	var wg sync.WaitGroup
	wg.Add(len(parties))

	var sigOut2 *common2.SignatureData

	for _, p := range parties {
		go func(p *party) {
			defer wg.Done()
			sig, sigOut, err := p.Sign(context.Background(), msg)
			sigOut2 = sigOut
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
		return nil, nil, fmt.Errorf(err.(string))
	}

	return sigs, sigOut2, nil
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
	pA := NewParty(1, logger("pA", t.Name()))
	pB := NewParty(2, logger("pB", t.Name()))
	pC := NewParty(3, logger("pC", t.Name()))

	addr := common.HexToAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
	tx := types.NewTx(&types.DynamicFeeTx{
		//ChainID:    big.NewInt(31337),
		ChainID:    big.NewInt(1),
		Nonce:      0,
		To:         &addr,
		Gas:        0x5208,
		GasTipCap:  big.NewInt(0x4de4fb81),
		GasFeeCap:  big.NewInt(0x4a76c17a4),
		Value:      big.NewInt(0x100),
		Data:       []byte{},
		AccessList: types.AccessList{},
	})

	hashed := tx.Hash().Bytes()
	var b bytes.Buffer
	fmt.Println(tx.EncodeRLP(&b))
	fmt.Println(hex.EncodeToString(b.Bytes()))
	fmt.Println(hex.EncodeToString(hashed))

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

	msgToSign := hashed

	t.Logf("Signing message")
	t1 = time.Now()
	sigs, sigOut, err := parties.sign(digest(msgToSign))
	assert.NoError(t, err)
	t.Logf("Signing completed in %v", time.Since(t1))

	sigSet := make(map[string]struct{})
	for _, s := range sigs {
		sigSet[string(s)] = struct{}{}
	}
	assert.Len(t, sigSet, 1)

	pk, err := parties[0].TPubKey()

	var sig struct {
		S, R *big.Int
	}
	sig.R = big.NewInt(0)
	sig.S = big.NewInt(0)
	sig.R.SetBytes(sigOut.R)
	sig.S.SetBytes(sigOut.S)

	assert.NoError(t, err)

	v := sigOut.GetSignatureRecovery()[0]

	assert.True(t, ecdsa.VerifyASN1(pk, digest(msgToSign), sigs[0]))
	assert.True(t, ecdsa.Verify(pk, hashed, sig.R, sig.S))
	fmt.Println("t", crypto.ValidateSignatureValues(v, sig.R, sig.S, true))
	fmt.Println("t", crypto.ValidateSignatureValues(v, sig.R, sig.S, false))
	pkey, _ := parties[0].ThresholdPK()
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign), sigOut.GetSignature()))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign), append(sigOut.GetSignature(), v)))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign)[:], sigOut.GetSignature()))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign)[:], append(sigOut.GetSignature(), v)))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign)[:], sigOut.GetSignature()[:]))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign)[:], append(sigOut.GetSignature(), v)[:]))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign), sigOut.GetSignature()[:]))
	fmt.Println("x", crypto.VerifySignature(pkey, digest(msgToSign), append(sigOut.GetSignature(), v)[:]))

	pubBytes := append(pk.X.Bytes(), pk.Y.Bytes()...)
	pubHex := hex.EncodeToString(pubBytes)
	asdf := common.BytesToAddress(common.FromHex(pubHex))
	fmt.Println("Public key in hex:", asdf)
	fmt.Println("PK", common.BytesToAddress(pkey))

	address, err := crypto.Ecrecover(hashed[:], append(sigOut.GetSignature(), v))
	if err == nil {
		fmt.Println("Ecrecover:", common.BytesToAddress(address))
	}
	fmt.Println("addr", address)
	address, err = crypto.Ecrecover(hashed[:], sigOut.GetSignature())
	fmt.Println("addr", address)
	address, err = crypto.Ecrecover(hashed, append(sigOut.GetSignature(), v))
	fmt.Println("addr", address)
	address, err = crypto.Ecrecover(hashed, sigOut.GetSignature())
	fmt.Println("addr", address)
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
