export interface VaultRecord {
  version?: number;
  salt: string;
  iv: string;
  data: string;
}
export interface Derivation {
  derive?(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array>;
  steps?(steps: Generator<number, Uint8Array>): Promise<Uint8Array>;
  check?(): void;
}
export class VaultState {
  close(): void;
}
export function url64(bytes: Iterable<number>): string;
export function generateVaultCode(): string;
export function vaultIterations(generated?: boolean): number;
export function keyFor(password: string, salt: Uint8Array, iterations: number, schedule?: Derivation): Promise<Uint8Array>;
export function seal(password: string, plaintext: string, iterations?: number, schedule?: Derivation, state?: VaultState): Promise<VaultRecord>;
export function unseal(password: string, record: VaultRecord, iterations?: number, schedule?: Derivation, state?: VaultState, options?: {legacy?: boolean}): Promise<string>;
export function probe(): Promise<boolean>;
export function scheduleKey(cx: import("gpui-kit").AsyncContext, steps: Generator<number, Uint8Array>, onProgress?: (progress: number, tick: import("gpui-kit").AsyncContext) => void, operation?: {check(): void}): Promise<Uint8Array>;
