import { describe, expect, test } from "vitest";
import { generateOts } from "./ots.test";

describe("OTS size", async () => {
  test("program size", async () => {
    const ots = await generateOts(1);

    const lsig = await ots.getLsig(0);

    expect(lsig.logic.byteLength).toMatchSnapshot();
  });

  test("program + arg size", async () => {
    const ots = await generateOts(1);

    const lsig = await ots.getLsig(0);

    const argSize = 64; // ed25519 signature size
    expect(lsig.logic.byteLength + argSize).toMatchSnapshot();
  });
});
