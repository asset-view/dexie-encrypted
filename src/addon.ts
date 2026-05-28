import Dexie from 'dexie';

import './extend-dexie-interface';
import { CryptoSettings, CryptoSettings2, EncryptDatabaseParams, tableEncryptionOptions } from './types';

import { applyMiddlewareWithCustomEncryption } from './applyMiddleware';
import { encryptWithNacl, decryptWithNacl } from './encryption-methods';


export function applyEncryptionMiddleware<T extends Dexie>(
  db: T,
  encryptionKey: Uint8Array | Promise<Uint8Array>,
  tableSettings: CryptoSettings<T>,
  onKeyChange: (db: T) => Promise<any>,
  _nonceOverrideForTesting?: Uint8Array
) {
  db.encryption = {
    version: '1',
    tableSettings: tableSettings as CryptoSettings2
  };
  applyMiddlewareWithCustomEncryption({
    db,
    encryptionKey,
    tableSettings,
    encrypt: encryptWithNacl,
    decrypt: decryptWithNacl,
    onKeyChange,
    _nonceOverrideForTesting,
  });
}

export function dexieEncryption<T extends Dexie>(options: {
  encryptionKey: Uint8Array | Promise<Uint8Array>,
  tableSettings: CryptoSettings<T>,
  onKeyChange: (db: T) => Promise<any>,
  _nonceOverrideForTesting?: Uint8Array}) {
  return (db: Dexie): void => {
    const origIdbName = db.name;
    db.encryption = {
      version: '1',
      tableSettings : options.tableSettings as CryptoSettings2
    }
    applyMiddlewareWithCustomEncryption({
      db : db as T,
      encryptionKey :options.encryptionKey,
      tableSettings: options.tableSettings,
      encrypt: encryptWithNacl,
      decrypt: decryptWithNacl,
      onKeyChange: options.onKeyChange,
      _nonceOverrideForTesting: options._nonceOverrideForTesting,
    });
  };
}