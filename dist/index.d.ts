import Dexie from 'dexie';
import { CryptoSettings } from './types';
export { cryptoOptions, CryptoSettings } from './types';
export declare const NON_INDEXED_FIELDS: "NON_INDEXED_FIELDS";
export declare const ENCRYPT_LIST: "ENCRYPT_LIST";
export declare const UNENCRYPTED_LIST: "UNENCRYPTED_LIST";
export { clearAllTables, clearEncryptedTables } from './applyMiddleware';
export declare function getAddon<T extends Dexie>(encryptionKey: Uint8Array | Promise<Uint8Array>, tableSettings: CryptoSettings<T>, onKeyChange: (db: T) => Promise<any>, _nonceOverrideForTesting?: Uint8Array): (db: T) => void;
export declare function applyEncryptionMiddleware<T extends Dexie>(db: T, encryptionKey: Uint8Array | Promise<Uint8Array>, tableSettings: CryptoSettings<T>, onKeyChange: (db: T) => Promise<any>, _nonceOverrideForTesting?: Uint8Array): void;
