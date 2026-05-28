import Dexie from 'dexie';
import nacl from 'tweetnacl';
import { encode, decode } from '@stablelib/utf8';
import Typeson from 'typeson';
import builtinTypes from 'typeson-registry/dist/presets/builtin';

const tableEncryptionOptions = {
    NON_INDEXED_FIELDS: 'NON_INDEXED_FIELDS',
    UNENCRYPTED_LIST: 'UNENCRYPTED_LIST',
    ENCRYPT_LIST: 'ENCRYPT_LIST',
};
const cryptoOptions = tableEncryptionOptions;

function encryptEntity(table, entity, rule, encryptionKey, performEncryption, nonceOverride) {
    if (rule === undefined) {
        return entity;
    }
    const indexObjects = table.schema.indexes;
    const indices = indexObjects.map((index) => index.keyPath);
    const dataToStore = {};
    const primaryKey = 'primKey' in table.schema
        ? table.schema.primKey.keyPath
        : table.schema.primaryKey.keyPath;
    const isPrimaryKey = (key) => {
        return key === primaryKey;
    };
    const isIndexed = (key) => {
        if (primaryKey === key)
            return true;
        for (const ix of indices) {
            if (!ix)
                continue;
            if (ix == key)
                return true;
            if (Array.isArray(ix) && ix.includes(key))
                return true;
            // Special Object.Field Index
            if (typeof entity[key] == 'object') {
                if (!Array.isArray(ix)) {
                    if (ix.startsWith(key) && ix.includes('.'))
                        return true;
                }
                else {
                    if (ix.find((x) => x.startsWith(key) && x.includes('.')))
                        return true;
                }
            }
        }
        return false;
    };
    if (rule === cryptoOptions.NON_INDEXED_FIELDS) {
        for (const key in entity) {
            if (isIndexed(key)) {
                dataToStore[key] = entity[key];
            }
            else {
                entity[key];
            }
        }
    }
    else if (rule.type === cryptoOptions.ENCRYPT_LIST) {
        for (const key in entity) {
            if (isPrimaryKey(key) === false && rule.fields.includes(key)) {
                entity[key];
            }
            else {
                dataToStore[key] = entity[key];
            }
        }
    }
    else {
        const whitelist = rule.type === cryptoOptions.UNENCRYPTED_LIST ? rule.fields : [];
        for (const key in entity) {
            if (isPrimaryKey(key) === false &&
                isIndexed(key) === false &&
                entity.hasOwnProperty(key) &&
                whitelist.includes(key) === false) {
                entity[key];
            }
            else {
                dataToStore[key] = entity[key];
            }
        }
    }
    // @ts-ignore
    dataToStore.__encryptedData = performEncryption(encryptionKey, entity, nonceOverride);
    return dataToStore;
}
function decryptEntity(entity, rule, encryptionKey, performDecryption) {
    if (!entity)
        return;
    if (rule === undefined || !entity.__encryptedData)
        return entity;
    const { __encryptedData, ...unencryptedFields } = entity;
    let decrypted = performDecryption(encryptionKey, __encryptedData);
    // Safety net for a rare, unreproduced bug where the write hook encrypts an
    // entity more than once. Unwrap any extra layers, warning on each one. Bail
    // out if a layer fails to decrypt (a custom decrypt() may return a falsy
    // value on failure) or if we exceed the layer cap, so a corrupt blob can
    // never spin this loop forever.
    const MAX_DECRYPTION_LAYERS = 16;
    let layers = 0;
    while (decrypted && decrypted.__encryptedData) {
        if (++layers > MAX_DECRYPTION_LAYERS) {
            throw new Error('Dexie-encrypted exceeded the maximum number of decryption layers.');
        }
        console.warn('DexieEncrypted', 'Double encryption detected');
        const decryptionAttempt = performDecryption(encryptionKey, decrypted.__encryptedData);
        if (!decryptionAttempt) {
            // Couldn't unwrap the extra layer; drop the dangling blob rather than
            // leak raw bytes into the returned object.
            delete decrypted.__encryptedData;
            break;
        }
        decrypted = decryptionAttempt;
    }
    return {
        ...unencryptedFields,
        ...decrypted,
    };
}
function installHooks(db, encryptionOptions, keyPromise, performEncryption, performDecryption, nonceOverride) {
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
                    const tableName = tn;
                    const table = downlevelDatabase.table(tableName);
                    if (tableName in encryptionOptions === false) {
                        return table; // No Encryption
                    }
                    const encryptionSetting = encryptionOptions[tableName];
                    const encrypt = (data) => {
                        return encryptEntity(table, data, encryptionSetting, encryptionKey, performEncryption, nonceOverride);
                    };
                    const decrypt = (data) => {
                        return decryptEntity(data, encryptionSetting, encryptionKey, performDecryption);
                    };
                    return {
                        ...table,
                        async openCursor(req) {
                            const cursor = await table.openCursor(req);
                            if (!cursor)
                                return null;
                            // Replace the Value Call via Proxy
                            const proxy = new Proxy(cursor, {
                                get(target, prop) {
                                    if (prop === 'value')
                                        return decrypt(cursor.value);
                                    return target[prop];
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
                                return Dexie.Promise.all(res.result.map(decrypt)).then((result) => ({
                                    ...res,
                                    result,
                                }));
                            });
                        },
                        async mutate(req) {
                            if (req.type === 'add' || req.type === 'put') {
                                return Dexie.Promise.all(req.values.map(encrypt)).then((values) => table.mutate({
                                    ...req,
                                    values,
                                }));
                            }
                            return table.mutate(req);
                        },
                    };
                },
            };
        },
    });
}

function compareArrays(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}
async function upgradeTables(db, tableSettings, encryptionKey, oldSettings, encrypt, decrypt, nonceOverride) {
    const unencryptedDb = new Dexie(db.name);
    // @ts-ignore
    const version = db._versions.find(v => v._cfg.version === db.verno);
    unencryptedDb.version(db.verno).stores(version._cfg.storesSource);
    await unencryptedDb.open();
    return Dexie.Promise.all(unencryptedDb.tables.map(async function (tbl) {
        const table = tbl;
        const oldSetting = oldSettings
            ? oldSettings[table.name]
            : undefined;
        const newSetting = tableSettings[table.name];
        if (oldSetting === newSetting) {
            // no upgrade needed.
            return Dexie.Promise.resolve();
        }
        if (oldSetting === undefined ||
            newSetting === undefined ||
            oldSetting === cryptoOptions.NON_INDEXED_FIELDS ||
            newSetting === cryptoOptions.NON_INDEXED_FIELDS) ;
        else {
            // both non-strings. Figure out if they're the same.
            // @ts-ignore will figure out later
            if (newSetting.type === oldSetting.type) {
                if (
                // @ts-ignore will figure out later
                compareArrays(newSetting.fields, oldSetting.fields)) {
                    // no upgrade needed.
                    return;
                }
            }
        }
        await table
            .toCollection()
            .modify((entity, ctx) => {
            const decrypted = decryptEntity(entity, oldSetting, encryptionKey, decrypt);
            ctx.value = encryptEntity(table, decrypted, newSetting, encryptionKey, encrypt, nonceOverride);
        });
        return;
    }));
}

function checkForKeyChange(db, oldSettings, encryptionKey, encrypt, decrypt, onKeyChange) {
    try {
        const changeDetectionObj = oldSettings
            ? oldSettings.keyChangeDetection
            : null;
        if (changeDetectionObj) {
            decrypt(encryptionKey, changeDetectionObj);
        }
    }
    catch (e) {
        return Dexie.Promise.resolve(onKeyChange(db));
    }
    return Dexie.Promise.resolve();
}

// Import some usable helper functions
const override = Dexie.override;
function overrideParseStoresSpec(origFunc) {
    return function (stores, dbSchema) {
        stores._encryptionSettings = '++id';
        // @ts-ignore
        return origFunc.call(this, stores, dbSchema);
    };
}
function applyMiddlewareWithCustomEncryption({ db, encryptionKey, tableSettings, onKeyChange, encrypt, decrypt, _nonceOverrideForTesting, }) {
    let keyPromise;
    if (encryptionKey instanceof Uint8Array) {
        if (encryptionKey.length !== 32) {
            throw new Error('Dexie-encrypted requires a Uint8Array of length 32 for an encryption key.');
        }
        keyPromise = Promise.resolve(encryptionKey);
        // @ts-ignore I want a runtime check below in case you're not using TS
    }
    else if ('then' in encryptionKey) {
        keyPromise = Dexie.Promise.resolve(encryptionKey);
    }
    else {
        throw new Error('Dexie-encrypted requires a Uint8Array of length 32 for an encryption key.');
    }
    // @ts-ignore
    db.Version.prototype._parseStoresSpec = override(
    // @ts-ignore
    db.Version.prototype._parseStoresSpec, overrideParseStoresSpec);
    if (db.verno > 0) {
        // Make sure new tables are added if calling encrypt after defining versions.
        try {
            db.version(db.verno).stores({});
        }
        catch (error) {
            throw new Error('Dexie-encrypt: The call to encrypt() cannot be done on an open database');
        }
    }
    installHooks(db, tableSettings, keyPromise, encrypt, decrypt, _nonceOverrideForTesting);
    db.on('ready', async () => {
        try {
            let encryptionSettings = db.table('_encryptionSettings');
            let oldSettings;
            try {
                oldSettings = await encryptionSettings.toCollection().last();
            }
            catch (e) {
                throw new Error("Dexie-encrypted can't find its encryption table. You may need to bump your database version.");
            }
            const encryptionKey = await keyPromise;
            if (encryptionKey instanceof Uint8Array === false ||
                encryptionKey.length !== 32) {
                throw new Error('Dexie-encrypted requires a Uint8Array of length 32 for a encryption key.');
            }
            await checkForKeyChange(db, oldSettings, encryptionKey, encrypt, decrypt, onKeyChange);
            await upgradeTables(db, tableSettings, encryptionKey, oldSettings?.settings, encrypt, decrypt, _nonceOverrideForTesting);
            await encryptionSettings.clear();
            await encryptionSettings.put({
                settings: tableSettings,
                keyChangeDetection: encrypt(encryptionKey, [1, 2, 3, 4, 5], new Uint8Array(24)),
            });
            return undefined;
        }
        catch (e) {
            return Dexie.Promise.reject(e);
        }
    });
}
function clearAllTables(db) {
    return Promise.all(db.tables.map(function (table) {
        return table.clear();
    }));
}
async function clearEncryptedTables(db) {
    let encryptionSettings = (await db
        .table('_encryptionSettings')
        .toCollection()
        .last()
        .catch(() => {
        throw new Error("Dexie-encrypted can't find its encryption table. You may need to bump your database version.");
    }));
    const promises = Object.keys(encryptionSettings.settings).map(async function (key) {
        await db.table(key).clear();
    });
    return Promise.all(promises);
}

const tson = new Typeson().register([builtinTypes]);
function encryptWithNacl(key, object, nonce) {
    if (nonce === undefined) {
        nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    }
    const stringified = tson.stringify(object);
    const encrypted = nacl.secretbox(encode(stringified), nonce, key);
    const data = new Uint8Array(nonce.length + encrypted.length);
    data.set(nonce);
    data.set(encrypted, nonce.length);
    return data;
}
function decryptWithNacl(encryptionKey, encryptedArray) {
    const nonce = encryptedArray.slice(0, nacl.secretbox.nonceLength);
    const message = encryptedArray.slice(nacl.secretbox.nonceLength, encryptedArray.length);
    const rawDecrypted = nacl.secretbox.open(message, nonce, encryptionKey);
    if (rawDecrypted === null) {
        throw new Error('Dexie-encrypted was unable to decrypt an entity.');
    }
    return tson.parse(decode(rawDecrypted));
}

function applyEncryptionMiddleware(db, encryptionKey, tableSettings, onKeyChange, _nonceOverrideForTesting) {
    db.encryption = {
        version: '1',
        tableSettings: tableSettings
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
function dexieEncryption(options) {
    return (db) => {
        db.name;
        db.encryption = {
            version: '1',
            tableSettings: options.tableSettings
        };
        applyMiddlewareWithCustomEncryption({
            db: db,
            encryptionKey: options.encryptionKey,
            tableSettings: options.tableSettings,
            encrypt: encryptWithNacl,
            decrypt: decryptWithNacl,
            onKeyChange: options.onKeyChange,
            _nonceOverrideForTesting: options._nonceOverrideForTesting,
        });
    };
}

const NON_INDEXED_FIELDS = cryptoOptions.NON_INDEXED_FIELDS;
const ENCRYPT_LIST = cryptoOptions.ENCRYPT_LIST;
const UNENCRYPTED_LIST = cryptoOptions.UNENCRYPTED_LIST;

export { ENCRYPT_LIST, NON_INDEXED_FIELDS, UNENCRYPTED_LIST, applyEncryptionMiddleware, clearAllTables, clearEncryptedTables, cryptoOptions, dexieEncryption as default };
//# sourceMappingURL=dexie-encrypted.mjs.map
