# TSS: Threshold Signature Scheme library

Currently, the build-in supported schemes are:
 - ECDSA (binance's [tss-lib](https://github.com/bnb-chain/tss-lib))
 - EdDSA (binance's [tss-lib](https://github.com/bnb-chain/tss-lib))
 - BLS   (builtin implementation)
 - [PS](https://github.com/IBM/TSS/tree/main/mpc/ps) (Pointcheval-Sanders)

### Repository structure:

- `disc`: Contains the discovery and synchronization module. Its role is to bootstrap the membership of the parties that are about to sign a message.

- `mpc`: Contains implementations of various threshold signature schemes. Currently the only available one is the Binance ECDSA TSS scheme. 

- `net`: Contains an implementation of a network module. Its role is to provide end to end encrypted and authenticated communication.

- `rbc`: Implements reliable byzantine fault tolerant broadcast. Its role is to ensure parties do not equivocate when broadcasting messages.

- `testutil`: Contains utilities used in tests, mostly TLS key generation.

- `test`: Contains integration tests that instantiate the TSS library with various threshold signature schemes found in `mpc`.

- `threshold`: Contains the TSS library, which orchestrates instances of `disc`, `mpc`, `rbc` and optionally `net`.

- `types`: Contains interface and type declaration.


### Go Module structure: 

The repository contains different go modules:

- `tss`: The main module of the library, receives threshold signature schemes as a dependency injection.
- `mpc/binance`: Wraps around the threshold signature scheme of binance-chain and presents an API that `tss` understands.
- `mpc/bls`: Implements a threshold BLS using [bn254](https://github.com/Consensys/gnark-crypto/tree/master/ecc/bn254) from [Gnark-crypto](https://github.com/Consensys/gnark-crypto).
- `test`: Contains integration tests that instantiate `tss` with all implementations in `mpc` (currently only `mpc/binance` and `mpc/bls`)

The `test` module imports both `tss` and `mpc/binance` but neither `tss` nor `mpc/binance` do not import one another. 


## Using the library

Each node that may participate in the threshold key generation phase or in the threshold signature phase must instantiate an instance of `threshold.Scheme`.
The instance can be obtained either by *explicitly* instantiating it and filling out its various public fields:

```
s := &threshold.Scheme{
   RBF: ...
   SyncFactory: ...
   ...
}
```

or alternatively by using the default construction method: `threshold.DefaultScheme(...)`.

By initializing the `threshold.Scheme` instance explicitly, it is possible to pass different implementations of its underlying dependencies (`rbc`, `disc`, etc.).

It is the responsibility of the consumer to ensure that messages that arrive to the party
are dispatched by the `threshold.Scheme` instance by calling `HandleMessage(msg *IncMessage)`.
The `IncMessage` struct appears below, and it is also the responsibility of the consumer to provide a secure, secret, and authenticated communication layer. 
The `net` package provides an implementation that fits the requirements, but it is not mandatory to use it.
```
type IncMessage struct {
	Data    []byte
	Source  uint16
	MsgType uint8
	Topic   []byte
}
```

#### What are universal identifiers and party identifiers? 

In a decentralized setting, two or more nodes may belong to the same company, institution, or just be administered by the same entities.


One of the dependencies of the `threshold.Scheme` is a function that returns the membership:

```
func() map[UniversalID]PartyID
```

A `UniversalID` uniquely defines a node within a network. The library expects that nodes with different universal identifiers will have different endpoints, or even be different hosts.

On the other hand, a `PartyID` is a unique identifier of *one or more* universal identifiers that belong to the same organization.
In every occurrence of a threshold protocol (either a key generation or a signature), each universal identifier may only correspond to a unique party identifier.
See the following example for motivation and clarity:


Consider a scenario where we have a threshold key that is secret shared across three different companies: `A`, `B`, `C`. 
Each company runs a node and has its own universal identifier, and it receives a single (secret) share of the private key.
Next, company `A` decides to replicate its secret share across three servers for high availability and load balancing.
Since company `A` now has several servers, but only one server at a time may participate in signing (or key generation), 
the library needs to distinguish the servers by their identifiers. 

However, in order for the `mpc` module to be simple, it shouldn't be aware of the fact that several identifiers may correspond to the same party.
To that end, the `mpc` module uses `PartyID` for its membership, and the rest of the modules (`rbc`, `disc`) use `UniversalID`. 
The `threshold` package performs translation between the two spaces in a way that is transparent to the `mpc` module. 

Note: Since the `mpc` module is pluggable and decoupled from this library, it does not reference the library. 
As a result, its API uses `uint16` instead of `PartyID`: 

```
Init(parties []uint16, threshold int, sendMsg func(msg []byte, isBroadcast bool, to uint16))

OnMsg(msgBytes []byte, from uint16, broadcast bool)
```

#### Generating a threshold public key

Before signing, the threshold public key needs to be generated by having the `threshold.Scheme` instance in each party invoke:

The `totalParties` is the number of shares this key needs to be split into, and `threshold` is the lowest number of shares
for which reconstruction of the secret is not possible.

```
secretData, err := KeyGen(ctx context.Context, totalParties, threshold int) ([]byte, error)
```

Then, the returned byte slice `secretData` needs to be stored in a secure and reliable place. 


#### Signing a message

After generating a public key, the `threshold.Scheme` instance needs to be initialized with the secret data.
To do that, simply assign the `StoredData` field:

```
// Initialize the instance, either explicitly, or using the a constructor function as below
s := threshold.LoudScheme(...) // Or, threshold.SilentScheme(...)
// Assign the secret data returned from KeyGen()
s.SetStoredData(secretData)
```

Then, two operations are available:

- `ThresholdPK() ([]byte, error)`: Returns the serialized threshold public key, encoded by the `mpc` dependency injected.


- `Sign(c context.Context, msg []byte, topic string) ([]byte, error)`: Signs `msg` in the context of given `topic`. Returns the signature encoded by the `mpc` dependency injected. 
To avoid denial of service by malicious parties that haven't received `msg`, `topic` must be unpredictable. 

#### Bootstrapping membership without communication

Before an instance of the TSS library can sign a message or generate a threshold key, it needs to discover who are the other parties
that will participate in the protocol. Furthermore, the library needs to be instantiated at each node 
running the protocol, else messages will be lost. There are two ways of achieving this:

1. Running a membership establishment protocol to have the parties discover each other and wait for each other to start

2. Decide deterministically who are the parties that will sign a message given its topic, and temporarily store protocol messages in memory and then insert them once the instance has started its
execution.

The first approach is implemented by the `LoudScheme` constructor method, while the second approach is implemented by the `SilentScheme` method.


#### Using threshold BLS:

When using BLS, the `threshold.Scheme` only orchestrates the key generation, but not the signing.

After generating the threshold key, persist the secret share of the party:
```
secretShareData, err := p.KeyGen(ctx, partynum, threshold)
saveToSafePlace(secretShareData)
```

Next, initialize a bls.TBLS instance and initialize it:
```
signer := &bls.TBLS{
	Logger: logger,
	Party:  uint16(id),
}

parties := []uint16{1, 2, 3}
signer.Init(parties, threshold, nil)
signer.SetShareData(secretShareData)
```

Get the public key from the initialized signer:

```
pk, err := signer.ThresholdPK()
```

And proceed to sign the message:

```
sig, err := signer.Sign(nil, msgHash)
```

Next, aggregate multiple signatures signed by distinct signers, but make sure each party identifier corresponds
to the correct signature, and verify the threshold signature returned:

```
var v bls.Verifier
err = v.Init(pk)
sig, err := v.AggregateSignatures([][]byte{sig1, sig3, []uint16{1, 3})
err = v.Verify(msgHash, sig)
```
