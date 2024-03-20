import { dexieEncryption, applyEncryptionMiddleware } from './addon';
export declare const NON_INDEXED_FIELDS: "NON_INDEXED_FIELDS";
export declare const ENCRYPT_LIST: "ENCRYPT_LIST";
export declare const UNENCRYPTED_LIST: "UNENCRYPTED_LIST";
export { cryptoOptions, CryptoSettings, CryptoSettings2 } from './types';
export { clearAllTables, clearEncryptedTables } from './applyMiddleware';
export { applyEncryptionMiddleware };
export default dexieEncryption;
