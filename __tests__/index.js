require('fake-indexeddb/auto');

const Dexie = require('dexie');
require('dexie-export-import');

const nacl = require('tweetnacl');

const {
    applyEncryptionMiddleware,
    clearAllTables,
    clearEncryptedTables,
    cryptoOptions,
} = require('../src/index');

const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32));

const dbToJson = (db) => {
    return new Promise(async (resolve) => {
        const blob = await db.export();
        const reader = new FileReader();
        reader.addEventListener('loadend', () => {
            const data = JSON.parse(reader.result);
            resolve(data);
        });
        reader.readAsText(blob);
    });
};

describe('API', () => {
    it('should be a function', () => {
        expect(typeof applyEncryptionMiddleware).toBe('function');
    });
    it('should have cleanup functions that are functions', () => {
        expect(typeof clearAllTables).toBe('function');
        expect(typeof clearEncryptedTables).toBe('function');
    });

    it('should have configs that are strings', () => {
        expect(typeof cryptoOptions.NON_INDEXED_FIELDS).toBe('string');
        expect(typeof cryptoOptions.UNENCRYPTED_LIST).toBe('string');
        expect(typeof cryptoOptions.ENCRYPT_LIST).toBe('string');
    });
});

describe('Encrypting', () => {
    it('should encrypt data', async () => {
        const db = new Dexie('MyDatabase');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });
        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            street: 'East 13:th Street',
            picture: 'camilla.png',
        };

        await db.friends.add(original);

        const readingDb = new Dexie('MyDatabase');
        readingDb.version(1).stores({
            friends: '++id, name, age',
        });
        applyEncryptionMiddleware(
            readingDb,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );
        await readingDb.open();
        const out = await readingDb.friends.get(1);
        expect(out).toEqual({ ...original, id: 1 });
    });

    it('should keep every member of a compound primary key in the clear', async () => {
        // Regression: a compound PK exposes its keyPath as an ARRAY. A member
        // that is not ALSO in a secondary index (here `key`) was treated as
        // non-indexed → encrypted and stripped from the top-level row, so the
        // `put` failed with "Evaluating the object store's key path did not
        // yield a value". `domain` survived only via the [domain+updatedAt]
        // secondary index. Both members must round-trip.
        const db = new Dexie('compound-pk');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                sysSessions: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );
        db.version(1).stores({
            sysSessions: '[domain+key], [domain+updatedAt], pluginUuid, updatedAt',
        });
        await db.open();

        const original = {
            domain: 'ai-chat',
            key: 'chat:app:5894f8cf-9071-4f81-961d-00bf8cb71009',
            pluginUuid: undefined,
            updatedAt: 1784645847749,
            state: { v: 1, messages: [{ role: 'user', content: 'hi' }] },
        };

        await expect(db.sysSessions.put(original)).resolves.toBeDefined();

        const out = await db.sysSessions.get(['ai-chat', original.key]);
        expect(out).toEqual(original);
    });

    it('should decrypt', async () => {
        const db = new Dexie('decrypt-test');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            street: 'East 13:th Street',
            picture: 'camilla.png',
        };

        await db.friends.add({ ...original });

        const out = await db.friends.get(1);
        delete out.id;
        expect(original).toEqual(out);
    });

    it('should decrypt when the database is closed and reopened', async () => {
        const db = new Dexie('decrypt-test-2');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            street: 'East 13:th Street',
            picture: 'camilla.png',
        };

        await db.friends.add({ ...original });

        const db2 = new Dexie('decrypt-test-2');
        applyEncryptionMiddleware(
            db2,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db2.version(1).stores({
            friends: '++id, name, age',
        });

        await db2.open();
        const out = await db2.friends.get(1);
        delete out.id;
        expect(original).toEqual(out);
    });

    it('should not modify your object', async () => {
        const db = new Dexie('MyDatabase');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            street: 'East 13:th Street',
            picture: 'camilla.png',
        };

        const earlyClone = { ...original };

        await db.friends.add(original);
        delete original.id;
        expect(original).toEqual(earlyClone);
    });

    it('should not explode if you get something undefined', async () => {
        const db = new Dexie('explode-undefined');

        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        db.version(1).stores({
            friends: '++id, name, age',
        });

        const val = await db.friends.get(1);
        expect(val).toBe(undefined);
    });

    it('should still work when you update an existing entity', async () => {
        const db = new Dexie('in-and-out-test');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            street: 'East 13:th Street',
            picture: 'camilla.png',
            isFriendly: true,
        };

        await db.friends.add({ ...original });

        const updated = {
            id: 1,
            name: 'Someone other than Camilla',
            age: 25,
            street: 'East 13,000:th Street',
            picture: 'camilla.png',
            isFriendly: false,
        };

        await db.friends.put(updated);

        const out = await db.friends.get(1);

        const readingDb = new Dexie('in-and-out-test');
        await readingDb.open();
        const data = await dbToJson(readingDb);

        expect(out).toEqual(updated);
    });

    it('should still work when you update a child object', async () => {
        const db = new Dexie('in-and-out-test');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            attrs: {
                picture: 'camilla.png',
                street: 'East 13:th Street',
            },
        };

        await db.friends.add({ ...original });

        const updated = {
            id: 1,
            name: 'Someone other than Camilla',
            age: 25,
            attrs: {
                picture: 'camilla.png',
                street: 'East 13,000:th Street',
            },
        };

        await db.friends.put(updated);

        const out = await db.friends.get(1);

        const readingDb = new Dexie('in-and-out-test');
        await readingDb.open();
        // const data = await dbToJson(readingDb);

        expect(out).toEqual(updated);
    });

    it('should still work when you have a key with dots in it', async () => {
        const db = new Dexie('dots-test');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, age',
        });

        await db.open();

        const original = {
            name: 'Camilla',
            age: 25,
            'upside.down': false,
            attrs: {
                picture: 'camilla.png',
                street: 'East 13:th Street',
            },
        };

        await db.friends.add({ ...original });

        const updated = {
            id: 1,
            name: 'Someone other than Camilla',
            age: 25,
            'upside.down': true,
            attrs: {
                picture: 'camilla.png',
                street: 'East 13,000:th Street',
            },
        };

        await db.friends.put(updated);

        const out = await db.friends.get(1);
        // const data = await dbToJson(db);
        // console.log(JSON.stringify(data, null, 4));

        expect(out).toEqual(updated);
    });

    it('should work with queries', async () => {
        const db = new Dexie('queries');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const data = [
            {
                name: 'Camilla',
                age: 25,
                street: 'East 13:th Street',
                picture: 'camilla.png',
            },
            {
                name: 'Allimac',
                age: 52,
                street: 'East 31:st Street',
                picture: 'allimac.png',
            },
        ];

        db.friends.bulkPut(data);

        const friend = await db.friends.where('age').above(40).toArray();

        expect(friend).toMatchInlineSnapshot(`
            [
              {
                "age": 52,
                "id": 2,
                "name": "Allimac",
                "picture": "allimac.png",
                "street": "East 31:st Street",
              },
            ]
        `);
    });

    it('should work with anyOf', async () => {
        const db = new Dexie('anyof');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const data = [
            {
                name: 'Camilla',
                age: 25,
                street: 'East 13:th Street',
                picture: 'camilla.png',
            },
            {
                name: 'Allimac',
                age: 52,
                street: 'East 31:st Street',
                picture: 'allimac.png',
            },
        ];

        db.friends.bulkPut(data);

        const friend = await db.friends.where('age').anyOf([25, 52]).toArray();

        expect(friend).toMatchInlineSnapshot(`
            [
              {
                "age": 25,
                "id": 1,
                "name": "Camilla",
                "picture": "camilla.png",
                "street": "East 13:th Street",
              },
              {
                "age": 52,
                "id": 2,
                "name": "Allimac",
                "picture": "allimac.png",
                "street": "East 31:st Street",
              },
            ]
        `);
    });

    it('should work with bulkGet', async () => {
        const db = new Dexie('anyof');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            {
                friends: cryptoOptions.NON_INDEXED_FIELDS,
            },
            clearAllTables,
            new Uint8Array(24)
        );

        // Declare tables, IDs and indexes
        db.version(1).stores({
            friends: '++id, name, age',
        });

        await db.open();

        const data = [
            {
                name: 'Camilla',
                age: 25,
                street: 'East 13:th Street',
                picture: 'camilla.png',
            },
            {
                name: 'Allimac',
                age: 25,
                street: 'East 31:st Street',
                picture: 'allimac.png',
            },
        ];

        db.friends.bulkPut(data);

        const friend = await db.friends.bulkGet([1, 2]);

        expect(friend).toMatchInlineSnapshot(`
            [
              {
                "age": 25,
                "id": 1,
                "name": "Camilla",
                "picture": "camilla.png",
                "street": "East 13:th Street",
              },
              {
                "age": 52,
                "id": 2,
                "name": "Allimac",
                "picture": "allimac.png",
                "street": "East 31:st Street",
              },
            ]
        `);
    });
});
