import { describe, it } from "vitest";
import { OneTimeSinger, type GetWrappedKey } from "../src";
import {
  algo,
  AlgorandClient,
  microAlgo,
} from "@algorandfoundation/algokit-utils";
import {
  BIP32DerivationType,
  fromSeed,
  harden,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { readFileSync } from "node:fs";

export async function generateOts(depth: number): Promise<OneTimeSinger> {
  const algorand = AlgorandClient.defaultLocalNet();

  const seed = crypto.getRandomValues(new Uint8Array(32));
  const rootKey = fromSeed(Buffer.from(seed));
  const xhd = new XHDWalletAPI();
  const getWrappedKey: GetWrappedKey = async (index: number) => {
    return {
      unwrapHdExtendedPrivateKey: async () => {
        return await xhd.deriveKey(
          rootKey,
          [harden(1337), harden(0), harden(index)],
          true,
          BIP32DerivationType.Peikert,
        );
      },
      wrapHdExtendedPrivateKey: async () => {},
    };
  };

  const sender = algorand.account.random();

  const ots = await OneTimeSinger.fromFile(
    sender,
    new Uint8Array(32),
    getWrappedKey,
    depth,
  );

  const start = performance.now();
  const firstLsig = await ots.getLsig(0);
  const end = performance.now();
  console.debug(`Generated ${depth}-key OTS chain in ${end - start}ms`);

  await algorand.account.ensureFundedFromEnvironment(sender, algo(1));

  await algorand.send.payment({
    sender,
    receiver: sender,
    amount: microAlgo(0),
    rekeyTo: firstLsig.address(),
  });

  return ots;
}

export async function withErr<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof Error && err.message.includes("pc=")) {
      const compiled =
        await AlgorandClient.defaultLocalNet().app.compileTealTemplate(
          readFileSync(
            __dirname + "/../contracts/out/OneTimeSig.teal",
            "utf-8",
          ),
          {
            NEXT_LSIG: new Uint8Array(32).fill(1),
            SENDER: new Uint8Array(32).fill(2),
            PUBKEY: new Uint8Array(32).fill(3),
            FALCON_PUBKEY_HASH: new Uint8Array(32).fill(4),
          },
        );

      const pc = err.message.match(/pc=(\d+)/)?.[1]!;
      const location = compiled.sourceMap.getLocationForPc(Number(pc));
      throw new Error(
        `Transaction failed at pc=${pc}, which corresponds to line ${location?.line} in the TEAL code`,
      );
    }

    throw err;
  }
}

describe.concurrent("OTS", async () => {
  const algorand = AlgorandClient.defaultLocalNet();

  it("should sign single txn", async () => {
    const ots = await generateOts(10);
    await algorand.send.payment({
      sender: ots,
      receiver: ots,
      amount: microAlgo(1),
    });
  });

  it("should sign multiple txns", async () => {
    const ots = await generateOts(10);
    await algorand.send.payment({
      sender: ots,
      receiver: ots,
      amount: microAlgo(1),
    });

    await algorand.send.payment({
      sender: ots,
      receiver: ots,
      amount: microAlgo(1),
    });
  });

  it("should sign grouped txns", async () => {
    const ots = await generateOts(10);
    await algorand
      .newGroup()
      .addPayment({
        sender: ots,
        receiver: ots,
        amount: microAlgo(1),
      })
      .addPayment({
        sender: ots,
        receiver: ots,
        amount: microAlgo(1),
      })
      .send();
  });
});
