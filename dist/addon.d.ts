import Dexie from 'dexie';
import './extend-dexie-interface';
import { CryptoSettings } from './types';
export declare function applyEncryptionMiddleware<T extends Dexie>(db: T, encryptionKey: Uint8Array | Promise<Uint8Array>, tableSettings: CryptoSettings<T>, onKeyChange: (db: T) => Promise<any>, _nonceOverrideForTesting?: Uint8Array): void;
export declare function dexieEncryption<T extends Dexie>(options: {
    encryptionKey: Uint8Array | Promise<Uint8Array>;
    tableSettings: CryptoSettings<T>;
    onKeyChange: (db: T) => Promise<any>;
    _nonceOverrideForTesting?: Uint8Array;
}): (db: Dexie) => void;
