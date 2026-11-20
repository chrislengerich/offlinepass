/**
 * Minimal CCID (chip-card interface device) transport over WebUSB.
 *
 * Talks to a YubiKey's CCID interface (the composite device's smartcard
 * interface, class 0x0B) using the PC_to_RDR_XfrBlock / R_to_PC_XfrBlock
 * exchange — the pass-through that carries one APDU per exchange.
 *
 * Chrome extension context: navigator.usb works in both the extension
 * pages and the service worker; the device pick needs a user gesture.
 */
export class Ccid {
  static YUBICO_VID = 0x1050;

  /** Opens the first YubiKey the user grants, claims its CCID interface,
   *  and remembers the bulk endpoints. The USB permission = per-plug
   *  (the same model as the Android app's ensureUsbPermission). */
  static async open(requestDevice = (f) => navigator.usb.requestDevice(f)) {
    const device = await requestDevice({
      filters: [{ vendorId: Ccid.YUBICO_VID }],
    });
    await device.open();
    // The CCID interface = the one with the smartcard class (0x0B).
    const ccid = device.configuration.interfaces.find((i) =>
      i.alternate.interfaceClass === 0x0b);
    if (!ccid) throw new Error("no CCID interface on the attached device");
    await device.claimInterface(ccid.interfaceNumber);
    const endpoints = {};
    for (const ep of ccid.alternate.endpoints) {
      if (ep.type === "bulk") endpoints[ep.direction] = ep.endpointNumber;
    }
    if (endpoints.out === undefined || endpoints.in === undefined) {
      throw new Error("no bulk endpoints on the CCID interface");
    }
    return new Ccid(device, ccid.interfaceNumber, endpoints.out, endpoints.in);
  }

  constructor(device, interfaceNumber, outEp, inEp) {
    this.device = device;
    this.interfaceNumber = interfaceNumber;
    this.outEp = outEp;
    this.inEp = inEp;
    this.seq = 0;
  }

  /** One CCID XfrBlock: the APDU in, the response (the status words
   *  included) out. The header = the 10-byte CCID bulk message. */
  async xfrBlock(apdu) {
    const header = new Uint8Array(10);
    header[0] = 0x6f;          // PC_to_RDR_XfrBlock
    header[1] = apdu.length & 0xff;
    header[2] = (apdu.length >>> 8) & 0xff;
    header[3] = (apdu.length >>> 16) & 0xff;
    header[4] = (apdu.length >>> 24) & 0xff;
    header[5] = 0x00;          // the slot 0
    header[6] = (++this.seq) & 0xff;
    header[7] = 0x00; header[8] = 0x00; header[9] = 0x00;
    // The AB protocol data structure: the command-level, no parameters.
    const ab = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    const frame = new Uint8Array(header.length + ab.length + apdu.length);
    frame.set(header, 0); frame.set(ab, header.length); frame.set(apdu, header.length + ab.length);

    await this.device.transferOut(this.outEp, frame);
    const reply = await this.device.transferIn(this.inEp, 65536);
    const data = new Uint8Array(reply.data.buffer);
    // The R_to_PC_XfrBlock: the 10-byte header + the payload.
    const payloadLen = data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24);
    if (data[0] !== 0x80) throw new Error(`CCID: unexpected message type 0x${data[0].toString(16)}`);
    const status = data[9];   // bStatus: the slot's ICC status
    if (status !== 0x00) throw new Error(`CCID: slot status 0x${status.toString(16)}`);
    return data.slice(10, 10 + payloadLen);
  }

  async close() {
    try { await this.device.releaseInterface(this.interfaceNumber); } catch (e) { /* */ }
    try { await this.device.close(); } catch (e) { /* */ }
  }
}
