import { dexieEncryption, applyEncryptionMiddleware } from './addon';
import { cryptoOptions } from './types';

export const NON_INDEXED_FIELDS = cryptoOptions.NON_INDEXED_FIELDS;
export const ENCRYPT_LIST = cryptoOptions.ENCRYPT_LIST;
export const UNENCRYPTED_LIST = cryptoOptions.UNENCRYPTED_LIST;
export { cryptoOptions, CryptoSettings, CryptoSettings2 } from './types';

export { clearAllTables, clearEncryptedTables } from './applyMiddleware';
export { applyEncryptionMiddleware };
    
export default dexieEncryption;
