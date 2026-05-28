import { DexieEncryptionAPI } from './DexieEncryptionAPI';
declare module 'dexie' {
    interface Dexie {
        encryption: DexieEncryptionAPI;
    }
    interface Table {
    }
    interface DexieConstructor {
        Encryption: {
            (db: Dexie): void;
            version: string;
        };
    }
}
