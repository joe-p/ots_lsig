# One-Time Signature LogicSig

This repo contains a reference implementation for a one-time signature (OTS) scheme via Algorand's Logic Signatures. The main goal is to prevent "harvest now, forge later" attacks from a quantum adversary. This scheme intends to be a middle-ground between classical signature schemes and PQ-secure schemes such as hash-based or lattice-based signatures, which are often significantly larger in size and harder to verify. Since this scheme uses Ed25519 signatures, it is also compatible with most existing key management systems.

## Comparison

| Scheme          | Public Key Size | Signature Size | Transactions Required |
| --------------- | --------------- | -------------- | --------------------- |
| Ed25519         | 32 bytes        | 64 bytes       | 1                     |
| FALCON-1024-DET | 1793 bytes      | 1232 bytes     | 3                     |
| OTS LogicSig    | 32 bytes        | 236\* bytes    | 1                     |

\* The underlying cryptographic signature is a regular 64-byte Ed25519 signature. The noted size accounts for the size of the entire logic signature program that is attached to every transaction.

## Overview

An OTS logic signature scheme is instantiated with a few parameters:

```ts
export type OtsParameters = {
  /** The Algorand address that this OTS chain has signing authority for. */
  sender: Addressable;
  /**
   * The FALCON-1024-DET public key that can be used as an escape hatch from the scheme.
   * This key will always be able to sign transactions for `sender`, regardless of the current state of the OTS key rotation
   */
  falconPubkey: Uint8Array;
  /**
   * The total number of keys in the OTS chain.
   * This determines how many times the OTS can be used to sign transactions before the chain is exhausted and can no longer be used.
   * Once exhausted, the `falconPubkey` can still be used to sign transactions for `sender`, potentially rotating to a new OTS chain if desired.
   */
  totalKeys: number;
};
```

Each logic signature in the OTS chain contains a commitment to a single Ed25519 public key and the next logic signature address it must rekey to. Once a new OTS chain is instantiated, the _last_ logic signature address is generated with a commitment to the zero address then logic sigs are generated backwards. Eventually there will be a generated logic signature for `totalKeys` Ed25519 public keys.

## Security

### Harvest Now, Forge Later

Ed25519 itself is not PQ-secure, but the hash function used for deriving Lsig addresses is. This means that if an adversary only has access to the logic sig address and not the underlying Ed25519 public key it contains, they cannot determine the public key thus cannot get the secret key. This is the basis of the "harvest now, forge later" security model of this scheme. Since every transaction requires the account to be rekeyed to the next logic signature address, the Ed25519 public key used for signing is always rotating and never public information until it is in the mempool for a transaction.

### Active Quantum Adversary

If there is an active quantum adversary watching the mempool, they could potentially use Shor's algorithim to derive the secret key, create a new transasction, and front-run your original transaction. This is a fairly complex attack and not only requires a quantum computer with enough error-correcting qubits to run Shor's algorithim but also have gates fast enough to run the algorithim before the original transaction is finalized. That being said, it is impossible to know how practical such an attack could be in the future thus this scheme should NOT be considered PQ-secure with active adversaries.

#### FALCON Escape Hatch

At any point the FALCON-1024-DET key can be used to sign transactions for the `sender` address and effectively bypass the OTS scheme. This is particularly useful if the user gives a high credence to the existance of active quantum adversaries in the mempool and wants to transition their account to a fully PQ-secure scheme.

#### Reduced Blast Radius

When a key in the chain is compromised, it is only that key that is compromised. Since the LogicSig is strict about the next address to rekey to, the adversary cannot use the compromised key to sign transactions that would rekey to a key they own. This means the adversary can use the compromised key for only one transactions, but then it must rekey back to the next that the honest user owns. If the user is dilligent about verifying transaction confirmations, they can immediately detect if a key is compromised and stop using the chain before any more keys are compromised. This is where the FALCON escape hatch can be useful to immediately transition to a new OTS chain if there is any suspicion of compromise.

### Trust Model

With a regular signature scheme it is trivial to verify that the secret key you own matches with the corresponding public key. With this OTS scheme, however, there are potentially thousands or millions of keys involved in generating the logic signatures. A malicious library could inject their own key in the chain without verification. The integrity of a OTS chain can be verified solely with public information (all the public keys in the chain). For this reason it is recommended to always verify the integrity of an OTS chain before using it. Using a seperate offline device to verify the integrity of the chain can further increase security by preventing potential supply chain attacks.

## Limitations

### Rekeying

Because this schemes requires specific values in the `rekeyTo` field for each transaction it is not possible to use OTS Ed25519 keys with any protocol that requires rekeying, such as ARC58. It is, however, possible to use the FALCON escape hatch key as long as there is room in the group (3 logic signatures)

### One Sender Address

Typically one Algorand address can be the auth address for many other address. The OTS address, however, can only approve transactions of the one address that is committed to within the program. One could creation a version of the scheme with multiple spend addresses but that is outside the scope of this reference implementation.

### dApp Compatibility

Since the usage of the logic signature always requires the `rekeyTo` field to be set, this scheme may be incompatible with dApps that expect specific transactions (that don't include `rekeyTo`) to be signed. Full compatibility for this OTS scheme within the ecosystem would require effort from both dApp developers and wallet developers.

#### Patches

For dApps that use the latest v10 of AlgoKit this reference implementation includes a monkey-patched `TransactionComposer.build` method that automatically sets the `rekeyTo` field for transactions that are signed with an OTS chain.

## Future Work

- Rust library for creating and verifying OTS chains in embedded devices such as hardware wallets
  - Ledger app
- Enshrining the "extension" pattern in AlgoKit for easier dApp and wallet compatibility
- Developer patches for other popular Algorand libraries, such as `algosdk` and older versions of AlgoKit utils
