<br />
<p align="center">
  <h2 align="center">subs</h2>
  <p align="center">
    🟠 <i>create, prove & verify Bitcoin handles off-chain</i>
    <br/>
   </p>
</p>


## How it works

**Basic principle**

1. Add handles to a Merkle tree & commit the 32-byte root to Bitcoin.

2. New handles must prove non-existence in the previous root(s).

3. Subs compresses these proofs: STARK or SNARK → root cert.

4. Owners get an inclusion proof → leaf cert.

5. Certificates are non-revocable: once bound to a script pubkey, it’s yours.

Note: Only the tree root gets committed to Bitcoin - certificates remain off-chain (low footprint!).

See https://github.com/buffrr/SIP-XXX


### Who gets to be the operator?

Operators are chosen via permissionless auctions on Bitcoin. They manage top-level spaces: https://explorer.spacesprotocol.org


## Installation

**Prereq (RISC Zero [toolchain](https://dev.risczero.com/api/zkvm/install)):**

```
curl -L https://risczero.com/install | bash
rzup install
```

Install subs:

```
git clone https://github.com/spacesprotocol/subs && cd subs
cargo install --path subs
```

For operators, use `--features metal` on macos or `cuda` for nvidia machines to enable GPU acceleration.

## Usage

### For end users

Example to request a handle:

```
$ subs request alice@bitcoin
✔ Created handle request
   → alice@bitcoin.req.json
   → Private key saved: alice@bitcoin.priv

Submit the request file to @bitcoin operator to get a certificate.
```

After getting a certificate, verify ownership:

```
$ subs verify alice@bitcoin.cert.json --root @bitcoin.cert.json
✔ Certificate verified
   → handle : alice@bitcoin
   → genesis: 85d3a410db41b317b7c0310df64cefb6504482c0b5c7e8a36c992ed0dfdb38af
   → anchor : dd101b1e3a52e97d2a71d518c7794ffc614260f39d38a307ae7274bc976b286b
```


### For operators

Add inclusion requests:

```bash
$ subs add alice@bitcoin.req.json
# or all in a directory (files named <subspace>@<space>.req.json)
$ subs add .
```

Commit changes:

```
$ subs commit
```

### Generating a root certificate (GPUs recommended)

Proving is the operator's responsibility, and generates the root certificate for the space.

To prove changes in the working directory:

```
$ subs prove
```

This will create a `@bitcoin.cert.json` with a STARK proof.


### Compress (STARK → SNARK, requires x86 for now)

```
$ subs compress
```

This will update `@bitcoin.cert.json` to use a smaller SNARK receipt.


### Issuing certificates

```
$ subs cert issue alice@bitcoin
```


## Using Remote provers

If you have a bonsai API key, you can run the prover remotely.

```bash
BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" subs compress
```


## License

This project is licensed under the [Apache 2.0](LICENSE).
