#!/bin/bash -e

cd test

cp go.mod go.mod.bck
cp go.sum go.sum.bck

echo "replace github.ibm.com/fabric-security-research/tss => ../" >> go.mod
echo "replace github.ibm.com/fabric-security-research/tss/mpc/binance/eddsa => ../mpc/binance/eddsa"  >> go.mod
echo "replace github.ibm.com/fabric-security-research/tss/mpc/binance/ecdsa => ../mpc/binance/ecdsa"  >> go.mod
go mod tidy

go test ./...

mv go.mod.bck go.mod
mv go.sum.bck go.sum