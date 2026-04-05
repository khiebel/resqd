/* tslint:disable */
/* eslint-disable */

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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
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
