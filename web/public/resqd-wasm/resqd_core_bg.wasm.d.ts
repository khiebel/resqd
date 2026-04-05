/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const canary_create: (a: number, b: number) => [number, number, number, number];
export const canary_rotate: (a: number, b: number) => [number, number, number, number];
export const canary_verify: (a: number, b: number) => [bigint, number, number];
export const decrypt_data: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const derive_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const encrypt_data: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const erasure_encode: (a: number, b: number) => [number, number, number, number];
export const erasure_reconstruct: (a: number, b: number, c: number) => [number, number, number, number];
export const generate_random_key: () => [number, number];
export const generate_salt: () => [number, number];
export const hash_bytes: (a: number, b: number) => [number, number];
export const hash_commit: (a: number, b: number, c: number, d: number) => [number, number];
export const kem_decapsulate: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const kem_encapsulate: (a: number, b: number) => [number, number, number, number];
export const kem_generate: () => [number, number, number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
