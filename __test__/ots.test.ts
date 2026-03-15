import { describe, it } from "vitest";
import { OneTimeSig, type GetWrappedKey } from "../src";
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

async function generateOts(depth: number): Promise<OneTimeSig> {
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

  const ots = await OneTimeSig.fromFile(
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
describe("OTS", async () => {
  const algorand = AlgorandClient.defaultLocalNet();

  it("should sign single txn", async () => {
    const ots = await generateOts(10);
    try {
      await algorand.send.payment({
        sender: ots,
        signer: await ots.getSigner(0),
        receiver: ots,
        rekeyTo: await ots.getLsig(1),
        amount: microAlgo(1),
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes("pc=")) {
        const compiled = await algorand.app.compileTealTemplate(
          readFileSync(
            __dirname + "/../contracts/out/OneTimeSig.teal",
            "utf-8",
          ),
          {
            NEXT_LSIG: new Uint8Array(32).fill(1),
            SENDER: ots.addr.publicKey,
            PUBKEY: new Uint8Array(32),
            FALCON_PUBKEY_HASH: new Uint8Array(32),
          },
        );

        const pc = err.message.match(/pc=(\d+)/)?.[1]!;
        const location = compiled.sourceMap.getLocationForPc(Number(pc));
        throw new Error(
          `Transaction failed at pc=${pc}, which corresponds to line ${location?.line} in the TEAL code`,
        );
      }
    }
  });
});
