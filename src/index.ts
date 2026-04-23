import { readFileSync } from "node:fs";
import {
  Address,
  AlgorandClient,
  TransactionComposer,
  type Addressable,
} from "@algorandfoundation/algokit-utils";
import {
  LogicSig,
  LogicSigAccount,
  Transaction,
  type AddressWithTransactionSigner,
  type TransactionSigner,
} from "@algorandfoundation/algokit-utils/transact";
import {
  ed25519SigningKeyFromWrappedSecret,
  type WrappedHdExtendedPrivateKey,
} from "@algorandfoundation/algokit-utils/crypto";
import path from "node:path";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import * as b32 from "hi-base32";

export type TemplateVariables = {
  nextLsig: LogicSig;
  sender: Address;
  pubkey: Uint8Array;
  falconPubkey: Uint8Array;
};

export type LsigTemplate = {
  program: Uint8Array;
  pubkeyOffset: number;
  falconPubkeyOffset: number;
  nextLsigOffset: number;
  senderOffset: number;
};

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

export type GetWrappedKey = (
  keyIndex: number,
) => Promise<WrappedHdExtendedPrivateKey>;

function rawPubkey(extendedSecretKey: Uint8Array): Uint8Array {
  const scalar = bytesToNumberLE(extendedSecretKey.subarray(0, 32));
  if ((scalar & (1n << 255n)) !== 0n) {
    throw new Error(
      "Invalid HD-expanded Ed25519 secret scalar: most-significant bit (bit 255) of the 32-byte scalar must be 0 for rawSign/rawPubkey inputs.",
    );
  }
  const reducedScalar = mod(scalar, ed25519.Point.Fn.ORDER);

  // pubKey = scalar * G
  const publicKey = ed25519.Point.BASE.multiply(reducedScalar);
  return publicKey.toBytes();
}

export class OneTimeSinger implements AddressWithTransactionSigner {
  private _lsigTemplate: LsigTemplate;

  addr: Address;

  get signer(): TransactionSigner {
    return async (txns: Transaction[], indexes: number[]) => {
      const stxns: Uint8Array[] = [];

      for (const index of indexes) {
        const txn = txns[index];

        if (!txn) {
          throw new Error(`Transaction index ${index} out of bounds`);
        }

        const keyIndex = this.nextKeyIndex++;
        const wrappedEsk = await this.getWrappedKey(keyIndex);

        const edKey = await ed25519SigningKeyFromWrappedSecret(wrappedEsk);
        const lsig = await this.getLsig(keyIndex);
        const idSig = await edKey.rawEd25519Signer(
          new Uint8Array(b32.decode.asBytes(txn.txId())),
        );
        const lsigAcct = new LogicSigAccount(lsig.logic, [idSig]);

        const stxn = (await lsigAcct.signer([txn], [0]))[0]!;

        stxns.push(stxn);
      }

      return stxns;
    };
  }

  falconPubkey: Uint8Array;

  private getWrappedKey: GetWrappedKey;

  readonly totalKeys: number;

  lsigAddressCache: Map<number, Address> = new Map();

  nextKeyIndex: number;

  private constructor(
    lsigTemplate: LsigTemplate,
    sender: Addressable,
    falconPubkey: Uint8Array,
    getWrappedKey: GetWrappedKey,
    totalKeys: number,
    nextKeyIndex = 0,
  ) {
    this._lsigTemplate = lsigTemplate;
    this.addr = sender.addr;
    this.falconPubkey = falconPubkey;
    this.getWrappedKey = getWrappedKey;
    this.totalKeys = totalKeys;
    this.nextKeyIndex = nextKeyIndex;
  }

  private async createAndCacheLsig(
    keyIndex: number,
    nextLsigAddr: Address,
  ): Promise<LogicSig> {
    const wrappedEsk = await this.getWrappedKey(keyIndex);
    const esk = await wrappedEsk.unwrapHdExtendedPrivateKey();
    const pubkey = rawPubkey(esk);
    esk.fill(0);
    const lsig = this.lsig(pubkey, nextLsigAddr);
    this.lsigAddressCache.set(keyIndex, lsig.address());
    return lsig;
  }

  async getLsig(keyIndex: number): Promise<LogicSig> {
    if (keyIndex > this.totalKeys) {
      throw new Error("No keys left in key chain");
    }

    let nextLsigAddr: Address = new Address(new Uint8Array(32).fill(0));

    for (let i = this.totalKeys; i > keyIndex; i--) {
      const cached = this.lsigAddressCache.get(i);
      if (cached) {
        nextLsigAddr = cached;
      } else {
        const lsig = await this.createAndCacheLsig(i, nextLsigAddr);
        nextLsigAddr = lsig.address();
      }
    }

    return await this.createAndCacheLsig(keyIndex, nextLsigAddr);
  }

  private lsig(
    pubkey: Uint8Array,
    nextLsig: Address,
    pqSalt: number = 0,
  ): LogicSig {
    const program = new Uint8Array(this._lsigTemplate.program);
    program.set(pubkey, this._lsigTemplate.pubkeyOffset);
    program.set(this.falconPubkey, this._lsigTemplate.falconPubkeyOffset);
    program.set(nextLsig.publicKey, this._lsigTemplate.nextLsigOffset);
    program.set(this.addr.publicKey, this._lsigTemplate.senderOffset);
    program.set([pqSalt], program.length - 1);

    const isEd25519 = (lsig: LogicSig) => {
      try {
        ed25519.Point.fromBytes(lsig.address().publicKey);
        return true;
      } catch (e) {
        if (e instanceof Error && e.message.includes("bad point")) {
          return false;
        }

        throw e;
      }
    };

    const lsig = new LogicSig(program);
    if (isEd25519(lsig)) {
      return this.lsig(pubkey, nextLsig, pqSalt + 1);
    }

    return lsig;
  }

  static async fromFile(
    sender: Addressable,
    falconPubkey: Uint8Array,
    getWrappedKey: GetWrappedKey,
    totalKeys: number,
  ): Promise<OneTimeSinger> {
    const algorand = AlgorandClient.defaultLocalNet();
    const teal =
      readFileSync(
        path.join(__dirname, "../contracts/out/OneTimeSig.teal"),
        "utf-8",
      ) + "\npushint 0";

    const compiled = (
      await algorand.app.compileTealTemplate(teal, {
        NEXT_LSIG: new Uint8Array(32).fill(1),
        SENDER: new Uint8Array(32).fill(2),
        PUBKEY: new Uint8Array(32).fill(3),
        FALCON_PUBKEY_HASH: new Uint8Array(32).fill(4),
      })
    ).compiledBase64ToBytes;

    console.debug(Buffer.from(compiled).toString("hex"));

    const findOffset = (placeholder: number): number => {
      for (let i = 0; i < compiled.length - 32; i++) {
        if (compiled.slice(i, i + 32).every((byte) => byte === placeholder)) {
          return i;
        }
      }

      throw new Error(
        `Placeholder ${placeholder} not found in compiled program`,
      );
    };

    const template = {
      program: compiled,
      nextLsigOffset: findOffset(1),
      senderOffset: findOffset(2),
      pubkeyOffset: findOffset(3),
      falconPubkeyOffset: findOffset(4),
    };

    return new OneTimeSinger(
      template,
      sender,
      falconPubkey,
      getWrappedKey,
      totalKeys,
    );
  }
}

const originalBuild = TransactionComposer.prototype.build;
TransactionComposer.prototype.build = async function () {
  // @ts-expect-error Accessing private field for transaction composer
  const { txns } = this;

  const indexes = new Map<Address, number>();
  for (const composerTxn of txns) {
    const txn = (composerTxn as any).data as {
      sender?: Addressable;
      rekeyTo?: Addressable;
    };
    if (!("sender" in txn)) {
      throw new Error("Unknown transaction type, expected sender field");
    }

    if (txn.sender instanceof OneTimeSinger) {
      const ots = txn.sender as OneTimeSinger;

      if (!indexes.has(ots.addr)) {
        indexes.set(ots.addr, ots.nextKeyIndex + 1);
      }

      console.debug(
        `Injecting rekey for transaction with OTS sender ${ots.addr} (key index ${indexes.get(ots.addr)!})`,
      );
      txn.rekeyTo = await ots.getLsig(indexes.get(ots.addr)!);
      indexes.set(ots.addr, indexes.get(ots.addr)! + 1);
    }
  }

  return await originalBuild.call(this);
};
