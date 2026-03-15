import {
  Account,
  type bytes,
  LogicSig,
  TemplateVar,
  Txn,
  assert,
  logicsig,
} from "@algorandfoundation/algorand-typescript";
import {
  arg,
  ed25519verifyBare,
  falconVerify,
  sha512_256,
} from "@algorandfoundation/algorand-typescript/op";

const NEXT_LSIG = TemplateVar<Account>("NEXT_LSIG");
const SENDER = TemplateVar<Account>("SENDER");
const PUBKEY = TemplateVar<bytes<32>>("PUBKEY");
const FALCON_PUBKEY_HASH = TemplateVar<bytes<32>>("FALCON_PUBKEY_HASH");

@logicsig({ avmVersion: 12 })
export class OneTimeSig extends LogicSig {
  program(): boolean {
    assert(Txn.sender === SENDER);

    const sig = arg(0);
    if (sig.length > 64) {
      const falconPubkey = arg(1);
      assert(
        sha512_256(falconPubkey) === FALCON_PUBKEY_HASH,
        "invalid falcon key",
      );

      falconVerify(Txn.txId, sig, falconPubkey);
      return true;
    }

    assert(Txn.rekeyTo === NEXT_LSIG);
    assert(
      ed25519verifyBare(Txn.txId, sig, PUBKEY),
      "ed25519 signature verification failed",
    );

    return true;
  }
}
