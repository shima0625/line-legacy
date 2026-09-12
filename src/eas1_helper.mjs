import net from "node:net";

const MAGIC = 0x31415345;
const OP_ENCRYPT_KEY = 1;
const OP_DECRYPT_KEY = 2;
const OP_RESET_CODEC = 3;
const OP_ENCODE = 4;
const OP_DECODE = 5;

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export class Eas1Helper {
  constructor(socketPath = "/run/line-eas1/eas1.sock") {
    this.socketPath = socketPath;
    this.socket = null;
    this.connecting = null;
    this.pending = null;
    this.received = Buffer.alloc(0);
    this.tail = Promise.resolve();
  }

  async connect() {
    if (this.socket && !this.socket.destroyed) return;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      let lastError;
      for (let attempt = 0; attempt < 30; attempt++) {
        try {
          await this.#connectOnce();
          return;
        } catch (error) {
          lastError = error;
          await delay(100);
        }
      }
      throw lastError ?? new Error("eas1 helper unavailable");
    })().finally(() => { this.connecting = null; });
    return this.connecting;
  }

  #connectOnce() {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ path: this.socketPath });
      const fail = (error) => {
        socket.destroy();
        reject(error);
      };
      socket.once("error", fail);
      socket.once("connect", () => {
        socket.off("error", fail);
        this.socket = socket;
        this.received = Buffer.alloc(0);
        socket.on("data", (chunk) => this.#onData(chunk));
        socket.on("error", (error) => this.#disconnect(error));
        socket.on("close", () => this.#disconnect(new Error("eas1 helper disconnected")));
        resolve();
      });
    });
  }

  #disconnect(error) {
    const socket = this.socket;
    this.socket = null;
    if (socket && !socket.destroyed) socket.destroy();
    if (this.pending) {
      const { reject } = this.pending;
      this.pending = null;
      reject(error);
    }
  }

  #onData(chunk) {
    this.received = Buffer.concat([this.received, chunk]);
    if (!this.pending || this.received.length < 12) return;
    const length = this.received.readUInt32LE(8);
    if (length > 4096) return this.#disconnect(new Error(`invalid eas1 response length ${length}`));
    if (this.received.length < 12 + length) return;
    const response = this.received.subarray(0, 12 + length);
    this.received = this.received.subarray(12 + length);
    const { resolve, reject } = this.pending;
    this.pending = null;
    const magic = response.readUInt32LE(0);
    const status = response.readInt32LE(4);
    if (magic !== MAGIC) reject(new Error("invalid eas1 helper response"));
    else if (status !== 0) reject(new Error(`eas1 helper status ${status}`));
    else resolve(Buffer.from(response.subarray(12)));
  }

  request(operation, payload = Buffer.alloc(0)) {
    const work = this.tail.then(async () => {
      await this.connect();
      const header = Buffer.alloc(12);
      header.writeUInt32LE(MAGIC, 0);
      header.writeUInt32LE(operation, 4);
      header.writeUInt32LE(payload.length, 8);
      return new Promise((resolve, reject) => {
        this.pending = { resolve, reject };
        this.socket.write(Buffer.concat([header, payload]), (error) => {
          if (error) this.#disconnect(error);
        });
      });
    });
    this.tail = work.catch(() => undefined);
    return work;
  }

  async encryptKey(key) {
    const input = Buffer.from(key);
    if (input.length !== 30) throw new Error("eas1 SRTP key must be 30 bytes");
    return this.request(OP_ENCRYPT_KEY, input);
  }

  async decryptKey(key) {
    const input = Buffer.from(key);
    if (input.length !== 30) throw new Error("eas1 SRTP key must be 30 bytes");
    return this.request(OP_DECRYPT_KEY, input);
  }

  async resetCodec() {
    await this.request(OP_RESET_CODEC);
  }

  async encode(samples) {
    if (samples.length !== 320) throw new Error(`eas1 encode requires 320 samples, got ${samples.length}`);
    const pcm = Buffer.alloc(640);
    for (let i = 0; i < samples.length; i++) pcm.writeInt16LE(samples[i], i * 2);
    return this.request(OP_ENCODE, pcm);
  }

  async decode(payload) {
    const pcm = await this.request(OP_DECODE, Buffer.from(payload));
    if (pcm.length !== 640) throw new Error(`eas1 decode returned ${pcm.length} bytes`);
    const samples = new Int16Array(320);
    for (let i = 0; i < samples.length; i++) samples[i] = pcm.readInt16LE(i * 2);
    return samples;
  }
}
