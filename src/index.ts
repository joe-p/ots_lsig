import { readFileSync } from "node:fs";
import {
  Address,
  AlgorandClient,
  type Addressable,
} from "@algorandfoundation/algokit-utils";
import { LogicSig } from "@algorandfoundation/algokit-utils/transact";
import {
  ed25519SigningKeyFromWrappedSecret,
  type WrappedHdExtendedPrivateKey,
} from "@algorandfoundation/algokit-utils/crypto";
import path from "node:path";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";

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

export class OneTimeSig {
  private _lsigTemplate: LsigTemplate;

  sender: Addressable;

  falconPubkey: Uint8Array;

  private getWrappedKey: GetWrappedKey;

  readonly totalKeys: number;

  lsigAddressCache: Map<number, Address> = new Map();

  private constructor(
    lsigTemplate: LsigTemplate,
    sender: Addressable,
    falconPubkey: Uint8Array,
    getWrappedKey: GetWrappedKey,
    totalKeys: number,
  ) {
    this._lsigTemplate = lsigTemplate;
    this.sender = sender;
    this.falconPubkey = falconPubkey;
    this.getWrappedKey = getWrappedKey;
    this.totalKeys = totalKeys;
  }

  async getLsig(keyIndex: number): Promise<LogicSig> {
    if (keyIndex > this.totalKeys) {
      throw new Error("Key index exceeds total keys");
    }

    let nextLsigAddr: Address = new Address(new Uint8Array(32).fill(255));

    for (let i = this.totalKeys - 1; i >= keyIndex; i--) {
      const cached = this.lsigAddressCache.get(i);
      if (cached) {
        nextLsigAddr = cached;
      } else {
        const wrappedEsk = await this.getWrappedKey(keyIndex);
        const esk = await wrappedEsk.unwrapHdExtendedPrivateKey();
        const pubkey = rawPubkey(esk);
        esk.fill(0);
        const lsig = this.lsig(pubkey, nextLsigAddr);
        this.lsigAddressCache.set(i, lsig.address());

        if (i === keyIndex) {
          return lsig;
        }
      }
    }

    throw new Error("Failed to generate LogicSig");
  }

  private lsig(pubkey: Uint8Array, nextLsig: Address): LogicSig {
    const program = new Uint8Array(this._lsigTemplate.program);
    program.set(pubkey, this._lsigTemplate.pubkeyOffset);
    program.set(this.falconPubkey, this._lsigTemplate.falconPubkeyOffset);
    program.set(nextLsig.publicKey, this._lsigTemplate.nextLsigOffset);
    program.set(this.sender.addr.publicKey, this._lsigTemplate.senderOffset);

    return new LogicSig(program);
  }

  static async fromFile(
    sender: Addressable,
    falconPubkey: Uint8Array,
    getWrappedKey: GetWrappedKey,
    totalKeys: number,
  ): Promise<OneTimeSig> {
    const algorand = AlgorandClient.defaultLocalNet();
    const teal = readFileSync(
      path.join(__dirname, "../contracts/out/OneTimeSig.teal"),
      "utf-8",
    );
    const compiled = (
      await algorand.app.compileTealTemplate(teal, {
        NEXT_LSIG: new Uint8Array(32).fill(1),
        SENDER: new Uint8Array(32).fill(2),
        PUBKEY: new Uint8Array(32).fill(3),
        FALCON_PUBKEY_HASH: new Uint8Array(32).fill(4),
      })
    ).compiledBase64ToBytes;

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

    return new OneTimeSig(
      template,
      sender,
      falconPubkey,
      getWrappedKey,
      totalKeys,
    );
  }
}
