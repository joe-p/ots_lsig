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
  it("should sign single txn", async () => {
    const ots = await generateOts(10);
  });
});
