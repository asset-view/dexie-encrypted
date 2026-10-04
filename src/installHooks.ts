import Dexie, {
  DBCoreTable,
  DBCoreIndex,
  DBCoreCursor,
  IndexSpec,
} from 'dexie';
import {
  CryptoSettings,
  TablesOf,
  TableType,
  EncryptionOption,
  cryptoOptions,
  EncryptionMethod,
  DecryptionMethod,
} from './types';

export function encryptEntity<T extends Dexie.Table>(
  table: DBCoreTable | T,
  entity: TableType<T>,
  rule: EncryptionOption<T> | undefined,
  encryptionKey: Uint8Array,
  performEncryption: EncryptionMethod,
  nonceOverride?: Uint8Array
) {
  if (rule === undefined) {
    return entity;
  }

  // We should never double-encrypt. decryptEntity strips __encryptedData, so a
  // value that has been read and written back never carries it. If we are
  // handed one that does, the caller is writing an un-decrypted row — encrypting
  // again would nest it. Refuse: store the row as-is, and surface the first
  // offending write (with a stack) so the source can be fixed.
  if (entity && (entity as any).__encryptedData) {
    console.warn(
      '[dexie-encrypted] Refused to double-encrypt: a write supplied an already-encrypted row (an un-decrypted row written back). Stored as-is — fix the write path.',
      new Error().stack
    );
    return entity;
  }

  const indexObjects = table.schema.indexes as (IndexSpec | DBCoreIndex)[];
  const indices = indexObjects.map((index) => index.keyPath);
  const toEncrypt: Partial<TableType<T>> = {};
  const dataToStore: Partial<TableType<T>> = {};

  const primaryKey =
    'primKey' in table.schema
      ? table.schema.primKey.keyPath
      : table.schema.primaryKey.keyPath;

  // A compound primary key (e.g. `[domain+key]`) exposes its keyPath as an
  // ARRAY of member field names. Comparing a string field against that array
  // is always false, so a PK member that isn't ALSO in a secondary index would
  // be treated as non-indexed → encrypted and stripped from the top-level row,
  // and IndexedDB's compound keyPath would then find no value on `put`.
  const isPrimaryKey = (key: string) => {
    return Array.isArray(primaryKey) ? primaryKey.includes(key) : key === primaryKey;
  };

  const isIndexed = (key: string) => {
    if (isPrimaryKey(key)) return true;
    for (const ix of indices) {
      if (!ix) continue;
      if (ix == key) return true;
      if (Array.isArray(ix) && ix.includes(key)) return true;
      // Special Object.Field Index
      if (typeof entity[key] == 'object') {
        if (!Array.isArray(ix)) {
          if (ix.startsWith(key) && ix.includes('.')) return true;
        } else {
          if (ix.find((x) => x.startsWith(key) && x.includes('.'))) return true;
        }
      }
    }
    return false;
  };

  if (rule === cryptoOptions.NON_INDEXED_FIELDS) {
    for (const key in entity) {
      if (isIndexed(key)) {
        dataToStore[key] = entity[key];
      } else {
        toEncrypt[key] = entity[key];
      }
    }
  } else if (rule.type === cryptoOptions.ENCRYPT_LIST) {
    for (const key in entity) {
      if (isPrimaryKey(key) === false && rule.fields.includes(key)) {
        toEncrypt[key] = entity[key];
      } else {
        dataToStore[key] = entity[key];
      }
    }
  } else {
    const whitelist =
      rule.type === cryptoOptions.UNENCRYPTED_LIST ? rule.fields : [];
    for (const key in entity) {
      if (
        isPrimaryKey(key) === false &&
        isIndexed(key) === false &&
        entity.hasOwnProperty(key) &&
        whitelist.includes(key) === false
      ) {
        toEncrypt[key] = entity[key];
      } else {
        dataToStore[key] = entity[key];
      }
    }
  }

  // @ts-ignore
  dataToStore.__encryptedData = performEncryption(
    encryptionKey,
    entity,
    nonceOverride
  );
  return dataToStore;
}

export function decryptEntity<T extends Dexie.Table>(
  entity: TableType<T> | undefined,
  rule: EncryptionOption<T> | undefined,
  encryptionKey: Uint8Array,
  performDecryption: DecryptionMethod
): TableType<T> | undefined {
  if (!entity) return;
  if (rule === undefined || !entity.__encryptedData) return entity;

  const { __encryptedData, ...unencryptedFields } = entity;

  let decrypted = performDecryption(encryptionKey, __encryptedData);

  // Count how many times this value was encrypted. The decryption above peeled
  // the first layer; each remaining __encryptedData is another layer, meaning it
  // was encrypted again (the double-encryption bug). Unwrap them all. Bail out
  // if a layer fails to decrypt (a custom decrypt() may return a falsy value on
  // failure) or if we exceed the cap, so a corrupt blob can never spin forever.
  const MAX_DECRYPTION_LAYERS = 16;
  let timesEncrypted = 1;
  while (decrypted && decrypted.__encryptedData) {
    if (timesEncrypted >= MAX_DECRYPTION_LAYERS) {
      throw new Error(
        'Dexie-encrypted exceeded the maximum number of decryption layers.'
      );
    }
    timesEncrypted++;
    const decryptionAttempt = performDecryption(
      encryptionKey,
      decrypted.__encryptedData
    );
    if (!decryptionAttempt) {
      // Couldn't unwrap the extra layer; drop the dangling blob rather than
      // leak raw bytes into the returned object.
      delete decrypted.__encryptedData;
      break;
    }
    decrypted = decryptionAttempt;
  }

  // Loud on every read of a multiply-encrypted row, reporting the depth.
  if (timesEncrypted > 1) {
    console.warn(`[dexie-encrypted] Data encrypted ${timesEncrypted} times`);
  }

  return {
    ...unencryptedFields,
    ...decrypted,
  };
}

export function installHooks<T extends Dexie>(
  db: T,
  encryptionOptions: CryptoSettings<T>,
  keyPromise: Promise<Uint8Array>,
  performEncryption: EncryptionMethod,
  performDecryption: DecryptionMethod,
  nonceOverride: Uint8Array | undefined
) {
  // this promise has to be resolved in order for the database to be open
  // but we also need to add the hooks before the db is open, so it's
  // guaranteed to happen before the key is actually needed.
  let encryptionKey = new Uint8Array(32);
  keyPromise.then((realKey) => {
    encryptionKey = realKey;
  });

  return db.use({
    stack: 'dbcore',
    name: 'encryption',
    level: 0,
    create(downlevelDatabase) {
      return {
        ...downlevelDatabase,
        table(tn) {
          // console.log('DEBUG', tn);
          const tableName = tn as keyof TablesOf<T>;
          const table = downlevelDatabase.table(tableName as string);
          if (tableName in encryptionOptions === false) {
            return table; // No Encryption
          }

          const encryptionSetting = encryptionOptions[tableName];
          const encrypt = (data: any) => {
            return encryptEntity(
              table,
              data,
              encryptionSetting,
              encryptionKey,
              performEncryption,
              nonceOverride
            );
          };
          const decrypt = (data: any) => {
            return decryptEntity(
              data,
              encryptionSetting,
              encryptionKey,
              performDecryption
            );
          };

          // ZONE-TRANSPARENT BY CONSTRUCTION: none of these may be `async`.
          //
          // A DBCore middleware sits inside Dexie's own promise chain. Declare
          // an operation `async` and its result reaches Dexie through a NATIVE
          // promise that adopts the Dexie promise. Dexie reads that adoption as
          // "a native await just ended" and takes one off its expected-awaits
          // count, which is ONE counter for the whole page, shared by every
          // database. Whichever transaction scope is inside a native await in
          // that tick loses its zone: its next operation runs in a transaction
          // of its own, the scope's transaction idles and commits, and the
          // scope rejects with "Transaction committed too early". The victim is
          // never the caller of this table, which is why it read as random.
          //
          // So every operation RETURNS the promise Dexie handed it (`.then` on
          // a Dexie promise is still a Dexie promise), the shape Dexie's own
          // middlewares use.
          return {
            ...table,
            openCursor(req) {
              return table.openCursor(req).then((cursor) => {
                if (!cursor) return null;
                // Replace the Value Call via Proxy
                const proxy = new Proxy(cursor, {
                  get(target: DBCoreCursor, prop: string) {
                    if (prop === 'value') return decrypt(cursor.value);
                    return (target as any)[prop];
                  },
                });
                return proxy;
              });
            },
            get(req) {
              return table.get(req).then(decrypt);
            },
            getMany(req) {
              return table.getMany(req).then((items) => {
                return items.map(decrypt);
              });
            },
            query(req) {
              return table.query(req).then((res) => {
                return Dexie.Promise.all(res.result.map(decrypt)).then(
                  (result) => ({
                    ...res,
                    result,
                  })
                );
              });
            },
            mutate(req) {
              if (req.type === 'add' || req.type === 'put') {
                // A throw while encrypting must still REJECT the write (it did
                // when this was `async`), never escape synchronously.
                let encrypted: any[];
                try {
                  encrypted = req.values.map(encrypt);
                } catch (error) {
                  return Dexie.Promise.reject(error);
                }
                return Dexie.Promise.all(encrypted).then((values) =>
                  table.mutate({
                    ...req,
                    values,
                  })
                );
              }
              return table.mutate(req);
            },
          };
        },
      };
    },
  });
}
