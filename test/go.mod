module github.com/IBM/TSS/test

go 1.18

require (
	github.com/IBM/TSS/mpc/binance/ecdsa v0.0.0-20230829113924-1fdc6af426a6
	github.com/IBM/TSS/mpc/binance/eddsa v0.0.0-20230829113924-1fdc6af426a6
	github.com/IBM/TSS/mpc/bls v0.0.0-20230829172216-b4ebe8f1ad89
	github.com/stretchr/testify v1.8.4
	go.uber.org/zap v1.24.0
)

require (
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/consensys/gnark-crypto v0.9.1 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

require (
	github.com/IBM/TSS v0.0.0-20230220083019-674e5367fe3b
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/bnb-chain/tss-lib v1.3.5 // indirect
	github.com/btcsuite/btcd v0.23.4 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/hashicorp/go-multierror v1.0.0 // indirect
	github.com/ipfs/go-log v0.0.1 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/opentracing/opentracing-go v1.1.0 // indirect
	github.com/otiai10/primes v0.0.0-20180210170552-f6d2a1ba97c4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/whyrusleeping/go-logging v0.0.0-20170515211332-0457bb6b88fc // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/sys v0.5.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

replace github.com/bnb-chain/tss-lib => ../mpc/binance/tss-lib
