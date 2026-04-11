/* tslint:disable */
/* eslint-disable */

/**
 * Streaming BLAKE3 hasher — call `update` repeatedly, then `finalizeHex`.
 * Used by the client-side streaming uploader to compute each shard's
 * expected content hash without holding the entire shard in memory.
 * This is the first rung of Track 2 (proof-of-absorption): the client
 * ships these hashes with the stream commit so a future server-side
 * random-range re-read can verify them.
 */
export class WasmBlake3Hasher {
    free(): void;
    [Symbol.dispose](): void;
    finalizeHex(): string;
    constructor();
    update(data: Uint8Array): void;
}

export class WasmStreamDecoder {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decode the next group. `shards_json` is a JSON array of 6 entries,
     * each either a base64 string or null (for a missing shard).
     */
    decodeGroup(shards_json: string): Uint8Array;
    finish(): void;
    groupsDecoded(): number;
    constructor(manifest_json: string);
}

/**
 * Stateful streaming decryptor. Create one per file, feed the same chunk
 * JSONs back in the order they were sealed, call `finish()` to assert
 * the stream was not truncated.
 */
export class WasmStreamDecryptor {
    free(): void;
    [Symbol.dispose](): void;
    chunksOpened(): number;
    /**
     * Call once all chunks have been opened. Returns an error if no
     * chunk was ever marked `is_last` (truncation attack).
     */
    finish(): void;
    /**
     * Create a decryptor from a 32-byte key and the header JSON returned
     * by `WasmStreamEncryptor.headerJson()`.
     */
    constructor(key: Uint8Array, header_json: string);
    /**
     * Open a sealed chunk (exactly the JSON returned by `sealChunk`).
     * Returns the plaintext bytes.
     */
    openChunk(chunk_json: string): Uint8Array;
}

export class WasmStreamEncoder {
    free(): void;
    [Symbol.dispose](): void;
    encodeGroup(input: Uint8Array): string;
    /**
     * Consume the encoder and return the StreamManifest as JSON.
     * Forward this verbatim to POST /vault/stream/commit. After calling
     * `finish`, any other method on this instance returns an error.
     */
    finishJson(): string;
    groupsEncoded(): number;
    constructor();
    /**
     * Total input bytes. Returned as string because u64 doesn't round-trip
     * through the JS Number type for files >2^53 bytes.
     */
    totalInputBytes(): string;
}

/**
 * Stateful streaming encryptor. Create one per file, call `sealChunk`
 * for each slice of plaintext, set `is_last=true` on the final slice.
 */
export class WasmStreamEncryptor {
    free(): void;
    [Symbol.dispose](): void;
    chunksSealed(): number;
    /**
     * Get the stream header as JSON. Persist this alongside the sealed
     * chunks and hand it to `WasmStreamDecryptor` on the read side.
     */
    headerJson(): string;
    isFinished(): boolean;
    constructor(key: Uint8Array, chunk_size: number);
    /**
     * Seal the next chunk. `is_last` MUST be true on the final chunk or
     * the decryptor will report a truncation error at `finish()`.
     * Returns JSON: `{"counter":N,"is_last":bool,"ciphertext_b64":"..."}`.
     */
    sealChunk(plaintext: Uint8Array, is_last: boolean): string;
}

/**
 * Create a new canary chain for an asset. Returns JSON.
 */
export function canary_create(asset_id: string): string;

/**
 * Rotate canary (call on every access). Takes chain JSON, returns updated JSON.
 */
export function canary_rotate(chain_json: string): string;

/**
 * Verify canary chain integrity. Returns access count or error.
 */
export function canary_verify(chain_json: string): bigint;

/**
 * Decrypt ciphertext. Takes JSON blob from encrypt_data + 32-byte key.
 */
export function decrypt_data(key: Uint8Array, blob_json: string): Uint8Array;

/**
 * Derive a 32-byte key from passphrase + 16-byte salt using Argon2id.
 */
export function derive_key(passphrase: string, salt: Uint8Array): Uint8Array;

/**
 * Encrypt plaintext with a 32-byte key. Returns JSON {nonce, ciphertext} (base64).
 */
export function encrypt_data(key: Uint8Array, plaintext: Uint8Array): string;

/**
 * Erasure-code data into 4+2 Reed-Solomon shards. Any 4 of 6 shards
 * reconstruct the original.
 *
 * Returns JSON `{shards: [base64, base64, ...], original_len: u32}`.
 * The caller uploads each shard to a separate storage backend and saves
 * `original_len` so decode knows how many bytes of padding to strip.
 */
export function erasure_encode(data: Uint8Array): string;

/**
 * Reconstruct original bytes from a (possibly incomplete) set of shards.
 *
 * `shards_json` must be a JSON array of length TOTAL_SHARDS (6) where each
 * slot is either a base64-encoded shard or `null`. At least DATA_SHARDS (4)
 * slots must be non-null.
 *
 * `original_len` must be the value returned by `erasure_encode` (tells the
 * decoder how many trailing pad bytes to strip).
 */
export function erasure_reconstruct(shards_json: string, original_len: number): Uint8Array;

/**
 * Generate a random 32-byte symmetric key.
 */
export function generate_random_key(): Uint8Array;

/**
 * Generate a random 16-byte salt.
 */
export function generate_salt(): Uint8Array;

/**
 * Hash bytes using BLAKE3. Returns hex string.
 */
export function hash_bytes(data: Uint8Array): string;

/**
 * Create a commitment hash: BLAKE3(data || context). Returns hex string.
 */
export function hash_commit(data: Uint8Array, context: Uint8Array): string;

/**
 * Decapsulate shared secret. Returns 32-byte shared secret (base64).
 */
export function kem_decapsulate(secret_key_b64: string, ciphertext_b64: string): string;

/**
 * Encapsulate shared secret with public key. Returns JSON {ciphertext, shared_secret}.
 */
export function kem_encapsulate(public_key_b64: string): string;

/**
 * Generate ML-KEM-768 keypair. Returns JSON {public_key, secret_key} (base64).
 */
export function kem_generate(): string;

/**
 * Generate a fresh X25519 identity keypair. Returns
 * `{"public_b64": "...", "private_b64": "..."}`. The caller is
 * responsible for sealing the private half under the master key before
 * persisting anywhere.
 */
export function x25519_generate_identity(): string;

/**
 * Derive the public half from a private X25519 scalar. Used by
 * `resqd-recover` to verify a recovery kit's public key matches the
 * sealed private key.
 */
export function x25519_public_from_private(private_b64: string): string;

/**
 * Recipient-side mirror of [`x25519_sender_wrap_key`]. Returns the same
 * 32-byte value that the sender computed (ECDH is symmetric).
 */
export function x25519_recipient_wrap_key(recipient_private_b64: string, sender_public_b64: string, asset_id: string): string;

/**
 * Sender-side: derive the wrap key used to encrypt a per-asset key for
 * a specific recipient and asset. Asset id is mixed in as HKDF `info`
 * so each (sender, recipient, asset) triple gets a domain-separated
 * wrap key.
 */
export function x25519_sender_wrap_key(sender_private_b64: string, recipient_public_b64: string, asset_id: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmblake3hasher_free: (a: number, b: number) => void;
    readonly __wbg_wasmstreamdecoder_free: (a: number, b: number) => void;
    readonly __wbg_wasmstreamdecryptor_free: (a: number, b: number) => void;
    readonly __wbg_wasmstreamencoder_free: (a: number, b: number) => void;
    readonly __wbg_wasmstreamencryptor_free: (a: number, b: number) => void;
    readonly canary_create: (a: number, b: number) => [number, number, number, number];
    readonly canary_rotate: (a: number, b: number) => [number, number, number, number];
    readonly canary_verify: (a: number, b: number) => [bigint, number, number];
    readonly decrypt_data: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derive_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encrypt_data: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly erasure_encode: (a: number, b: number) => [number, number, number, number];
    readonly erasure_reconstruct: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generate_random_key: () => [number, number];
    readonly generate_salt: () => [number, number];
    readonly hash_bytes: (a: number, b: number) => [number, number];
    readonly hash_commit: (a: number, b: number, c: number, d: number) => [number, number];
    readonly kem_decapsulate: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly kem_encapsulate: (a: number, b: number) => [number, number, number, number];
    readonly kem_generate: () => [number, number, number, number];
    readonly wasmblake3hasher_finalizeHex: (a: number) => [number, number];
    readonly wasmblake3hasher_new: () => number;
    readonly wasmblake3hasher_update: (a: number, b: number, c: number) => void;
    readonly wasmstreamdecoder_decodeGroup: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmstreamdecoder_finish: (a: number) => [number, number];
    readonly wasmstreamdecoder_groupsDecoded: (a: number) => number;
    readonly wasmstreamdecoder_new: (a: number, b: number) => [number, number, number];
    readonly wasmstreamdecryptor_chunksOpened: (a: number) => number;
    readonly wasmstreamdecryptor_finish: (a: number) => [number, number];
    readonly wasmstreamdecryptor_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmstreamdecryptor_openChunk: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmstreamencoder_encodeGroup: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmstreamencoder_finishJson: (a: number) => [number, number, number, number];
    readonly wasmstreamencoder_groupsEncoded: (a: number) => number;
    readonly wasmstreamencoder_new: () => [number, number, number];
    readonly wasmstreamencoder_totalInputBytes: (a: number) => [number, number];
    readonly wasmstreamencryptor_headerJson: (a: number) => [number, number, number, number];
    readonly wasmstreamencryptor_isFinished: (a: number) => number;
    readonly wasmstreamencryptor_new: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmstreamencryptor_sealChunk: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly x25519_generate_identity: () => [number, number, number, number];
    readonly x25519_public_from_private: (a: number, b: number) => [number, number, number, number];
    readonly x25519_recipient_wrap_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly x25519_sender_wrap_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasmstreamencryptor_chunksSealed: (a: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
