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

  const indexObjects = table.schema.indexes as (IndexSpec | DBCoreIndex)[];
  const indices = indexObjects.map((index) => index.keyPath);
  const toEncrypt: Partial<TableType<T>> = {};
  const dataToStore: Partial<TableType<T>> = {};

  const primaryKey =
    'primKey' in table.schema
      ? table.schema.primKey.keyPath
      : table.schema.primaryKey.keyPath;

  const isPrimaryKey = (key: string) => {
    return key === primaryKey;
  };

  const isIndexed = (key: string) => {
    if (primaryKey === key) return true;
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

  // There is a bug that causes double encryption. I am not sure what causes it,
  // it is very rare and I have no repro steps. I believe the hook is running twice
  // in very rare circumstances, but I have no evidence of it.
  // This decrypts until all decryption is done. The only circumstance where it will
  // create an undesireable result is if your data has an __encryptedData key, and
  // that data can be decrypted by the performDecryption function.
  let count = 0;
  while (decrypted.__encryptedData) {
    count++;
    const decryptionAttempt = performDecryption(
      encryptionKey,
      decrypted.__encryptedData
    );
    if (decryptionAttempt) decrypted = decryptionAttempt;
    if (count > 1) console.warn('DexieEncrypted', 'Double encryption detected');
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

          return {
            ...table,
            async openCursor(req) {
              const cursor = await table.openCursor(req);
              if (!cursor) return null;
              // Replace the Value Call via Proxy
              const proxy = new Proxy(cursor, {
                get(target: DBCoreCursor, prop: string) {
                  if (prop === 'value') return decrypt(cursor.value);
                  return (target as any)[prop];
                },
              });
              return proxy;
            },
            async get(req) {
              return table.get(req).then(decrypt);
            },
            async getMany(req) {
              return table.getMany(req).then((items) => {
                return items.map(decrypt);
              });
            },
            async query(req) {
              return table.query(req).then((res) => {
                return Dexie.Promise.all(res.result.map(decrypt)).then(
                  (result) => ({
                    ...res,
                    result,
                  })
                );
              });
            },
            async mutate(req) {
              if (req.type === 'add' || req.type === 'put') {
                return Dexie.Promise.all(req.values.map(encrypt)).then(
                  (values) =>
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
