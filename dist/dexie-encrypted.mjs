import Dexie from 'dexie';
import nacl from 'tweetnacl';
import { encode, decode } from '@stablelib/utf8';
import Typeson from 'typeson';
import builtinTypes from 'typeson-registry/dist/presets/builtin';

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise, SuppressedError, Symbol */


function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
};

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
    const indices = indexObjects.map(index => index.keyPath);
    const dataToStore = {};
    const primaryKey = 'primKey' in table.schema ? table.schema.primKey.keyPath : table.schema.primaryKey.keyPath;
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
                    if (ix.find(x => x.startsWith(key) && x.includes('.')))
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
    const { __encryptedData } = entity, unencryptedFields = __rest(entity, ["__encryptedData"]);
    let decrypted = performDecryption(encryptionKey, __encryptedData);
    // There is a bug that causes double encryption. I am not sure what causes it,
    // it is very rare and I have no repro steps. I believe the hook is running twice
    // in very rare circumstances, but I have no evidence of it.
    // This decrypts until all decryption is done. The only circumstance where it will
    // create an undesireable result is if your data has an __encryptedData key, and
    // that data can be decrypted by the performDecryption function.
    while (decrypted.__encryptedData) {
        const decryptionAttempt = performDecryption(encryptionKey, decrypted.__encryptedData);
        if (decryptionAttempt) {
            decrypted = decryptionAttempt;
        }
    }
    return Object.assign(Object.assign({}, unencryptedFields), decrypted);
}
function installHooks(db, encryptionOptions, keyPromise, performEncryption, performDecryption, nonceOverride) {
    // this promise has to be resolved in order for the database to be open
    // but we also need to add the hooks before the db is open, so it's
    // guaranteed to happen before the key is actually needed.
    let encryptionKey = new Uint8Array(32);
    keyPromise.then(realKey => {
        encryptionKey = realKey;
    });
    return db.use({
        stack: 'dbcore',
        name: 'encryption',
        level: 0,
        create(downlevelDatabase) {
            return Object.assign(Object.assign({}, downlevelDatabase), { table(tn) {
                    // console.log('DEBUG', tn);
                    const tableName = tn;
                    const table = downlevelDatabase.table(tableName);
                    if (tableName in encryptionOptions === false) {
                        return table;
                    }
                    const encryptionSetting = encryptionOptions[tableName];
                    function encrypt(data) {
                        return encryptEntity(table, data, encryptionSetting, encryptionKey, performEncryption, nonceOverride);
                    }
                    function decrypt(data) {
                        return decryptEntity(data, encryptionSetting, encryptionKey, performDecryption);
                    }
                    return Object.assign(Object.assign({}, table), { openCursor(req) {
                            return table.openCursor(req).then(cursor => {
                                if (!cursor) {
                                    return cursor;
                                }
                                return Object.create(cursor, {
                                    continue: {
                                        get() {
                                            return cursor.continue;
                                        },
                                    },
                                    continuePrimaryKey: {
                                        get() {
                                            return cursor.continuePrimaryKey;
                                        },
                                    },
                                    key: {
                                        get() {
                                            return cursor.key;
                                        },
                                    },
                                    value: {
                                        get() {
                                            return decrypt(cursor.value);
                                        },
                                    },
                                });
                            });
                        },
                        get(req) {
                            return table.get(req).then(decrypt);
                        },
                        getMany(req) {
                            return table.getMany(req).then(items => {
                                return items.map(decrypt);
                            });
                        },
                        query(req) {
                            return table.query(req).then(res => {
                                return Dexie.Promise.all(res.result.map(decrypt)).then(result => (Object.assign(Object.assign({}, res), { result })));
                            });
                        },
                        mutate(req) {
                            if (req.type === 'add' || req.type === 'put') {
                                return Dexie.Promise.all(req.values.map(encrypt)).then(values => table.mutate(Object.assign(Object.assign({}, req), { values })));
                            }
                            return table.mutate(req);
                        } });
                } });
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
function upgradeTables(db, tableSettings, encryptionKey, oldSettings, encrypt, decrypt, nonceOverride) {
    return __awaiter(this, void 0, void 0, function* () {
        const unencryptedDb = new Dexie(db.name);
        // @ts-ignore
        const version = db._versions.find((v) => v._cfg.version === db.verno);
        unencryptedDb.version(db.verno).stores(version._cfg.storesSource);
        yield unencryptedDb.open();
        return Dexie.Promise.all(unencryptedDb.tables.map(function (tbl) {
            return __awaiter(this, void 0, void 0, function* () {
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
                yield table
                    .toCollection()
                    .modify((entity, ctx) => {
                    const decrypted = decryptEntity(entity, oldSetting, encryptionKey, decrypt);
                    ctx.value = encryptEntity(table, decrypted, newSetting, encryptionKey, encrypt, nonceOverride);
                });
                return;
            });
        }));
    });
}

function checkForKeyChange(db, oldSettings, encryptionKey, encrypt, decrypt, onKeyChange) {
    try {
        const changeDetectionObj = oldSettings ? oldSettings.keyChangeDetection : null;
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
    db.on('ready', () => __awaiter(this, void 0, void 0, function* () {
        try {
            let encryptionSettings = db.table('_encryptionSettings');
            let oldSettings;
            try {
                oldSettings = yield encryptionSettings.toCollection().last();
            }
            catch (e) {
                throw new Error("Dexie-encrypted can't find its encryption table. You may need to bump your database version.");
            }
            const encryptionKey = yield keyPromise;
            if (encryptionKey instanceof Uint8Array === false || encryptionKey.length !== 32) {
                throw new Error('Dexie-encrypted requires a Uint8Array of length 32 for a encryption key.');
            }
            yield checkForKeyChange(db, oldSettings, encryptionKey, encrypt, decrypt, onKeyChange);
            yield upgradeTables(db, tableSettings, encryptionKey, oldSettings === null || oldSettings === void 0 ? void 0 : oldSettings.settings, encrypt, decrypt, _nonceOverrideForTesting);
            yield encryptionSettings.clear();
            yield encryptionSettings.put({
                settings: tableSettings,
                keyChangeDetection: encrypt(encryptionKey, [1, 2, 3, 4, 5], new Uint8Array(24)),
            });
            return undefined;
        }
        catch (e) {
            return Dexie.Promise.reject(e);
        }
    }));
}
function clearAllTables(db) {
    return Promise.all(db.tables.map(function (table) {
        return table.clear();
    }));
}
function clearEncryptedTables(db) {
    return __awaiter(this, void 0, void 0, function* () {
        let encryptionSettings = (yield db
            .table('_encryptionSettings')
            .toCollection()
            .last()
            .catch(() => {
            throw new Error("Dexie-encrypted can't find its encryption table. You may need to bump your database version.");
        }));
        const promises = Object.keys(encryptionSettings.settings).map(function (key) {
            return __awaiter(this, void 0, void 0, function* () {
                yield db.table(key).clear();
            });
        });
        return Promise.all(promises);
    });
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

const NON_INDEXED_FIELDS = cryptoOptions.NON_INDEXED_FIELDS;
const ENCRYPT_LIST = cryptoOptions.ENCRYPT_LIST;
const UNENCRYPTED_LIST = cryptoOptions.UNENCRYPTED_LIST;
function getAddon(encryptionKey, tableSettings, onKeyChange, _nonceOverrideForTesting) {
    return (db) => {
        applyMiddlewareWithCustomEncryption({
            db,
            encryptionKey,
            tableSettings,
            encrypt: encryptWithNacl,
            decrypt: decryptWithNacl,
            onKeyChange,
            _nonceOverrideForTesting,
        });
    };
}
function applyEncryptionMiddleware(db, encryptionKey, tableSettings, onKeyChange, _nonceOverrideForTesting) {
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

export { ENCRYPT_LIST, NON_INDEXED_FIELDS, UNENCRYPTED_LIST, applyEncryptionMiddleware, clearAllTables, clearEncryptedTables, cryptoOptions, getAddon };
//# sourceMappingURL=dexie-encrypted.mjs.map
