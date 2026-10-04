require('fake-indexeddb/auto');

const Dexie = require('dexie');
const nacl = require('tweetnacl');

const {
    applyEncryptionMiddleware,
    clearAllTables,
    cryptoOptions,
} = require('../src/index');

const keyPair = nacl.sign.keyPair.fromSeed(new Uint8Array(32));

const encryptedDb = async (name) => {
    const db = new Dexie(name);
    applyEncryptionMiddleware(
        db,
        keyPair.publicKey,
        { friends: cryptoOptions.NON_INDEXED_FIELDS },
        clearAllTables,
        new Uint8Array(24)
    );
    db.version(1).stores({ friends: '++id, name' });
    await db.open();
    return db;
};

/**
 * A DBCore middleware sits inside Dexie's own promise chain, and Dexie counts
 * native awaits with ONE counter for the whole page. An `async` table operation
 * hands its result back through a native promise that adopts the Dexie promise;
 * Dexie reads that adoption as "a native await ended" and takes one off the
 * count. Whichever OTHER transaction scope is inside a native await in that tick
 * loses its zone: its next operation runs in a transaction of its own, the
 * scope's transaction idles and commits, and the scope rejects with
 * "Transaction committed too early".
 */
describe('Zone transparency', () => {
    const operations = ['openCursor', 'get', 'getMany', 'query', 'mutate'];

    it('declares no table operation async and returns the Dexie promise it was handed', async () => {
        const db = await encryptedDb('zone-shape');
        const middleware = db._middlewares.dbcore.find(
            (entry) => entry.name === 'encryption'
        );

        const answer = { result: [], numFailures: 0, failures: {} };
        const downTable = { name: 'friends', schema: db.core.table('friends').schema };
        for (const op of operations) {
            downTable[op] = () => Dexie.Promise.resolve(op === 'openCursor' ? null : answer);
        }
        const table = middleware.create({ table: () => downTable }).table('friends');

        for (const op of operations) {
            expect(table[op].constructor.name).not.toBe('AsyncFunction');
        }
        expect(table.get({ key: 1 })).toBeInstanceOf(Dexie.Promise);
        expect(table.getMany({ keys: [1] })).toBeInstanceOf(Dexie.Promise);
        expect(table.query({ query: {} })).toBeInstanceOf(Dexie.Promise);
        expect(table.openCursor({ query: {} })).toBeInstanceOf(Dexie.Promise);
        expect(
            table.mutate({ type: 'put', values: [{ id: 1, name: 'a' }] })
        ).toBeInstanceOf(Dexie.Promise);
        expect(table.mutate({ type: 'delete', keys: [1] })).toBeInstanceOf(
            Dexie.Promise
        );
    });

    it('rejects a write whose encryption throws, rather than throwing synchronously', async () => {
        const db = new Dexie('zone-reject');
        applyEncryptionMiddleware(
            db,
            keyPair.publicKey,
            { friends: cryptoOptions.NON_INDEXED_FIELDS },
            clearAllTables,
            new Uint8Array(24)
        );
        db.version(1).stores({ friends: '++id, name' });
        await db.open();
        const middleware = db._middlewares.dbcore.find(
            (entry) => entry.name === 'encryption'
        );
        // A table with no index list makes `encrypt` throw (a TypeError).
        const downTable = {
            name: 'friends',
            schema: {},
            mutate: () => Dexie.Promise.resolve({ numFailures: 0, failures: {} }),
        };
        const table = middleware.create({ table: () => downTable }).table('friends');

        let returned;
        expect(() => {
            returned = table.mutate({ type: 'put', values: [{ name: 'a', secret: 1 }] });
        }).not.toThrow();
        await expect(returned).rejects.toThrow(TypeError);
    });

    it('does not take the zone from another transaction that is inside a native await', async () => {
        const encrypted = await encryptedDb('zone-encrypted');
        await encrypted.friends.add({ name: 'Camilla', street: 'East 13:th Street' });

        const plain = new Dexie('zone-plain');
        plain.version(1).stores({ rows: 'id' });
        await plain.open();
        await plain.rows.put({ id: 1 });

        // A native async helper with an await of its own: no Dexie operation is
        // pending while it settles, so only Dexie's zone echo carries the zone.
        const inner = async () => 1;
        const nativeHelper = async () => (await inner()) + 1;

        let zoneAfterHelper;
        const scope = plain.transaction('r', plain.rows, async () => {
            const transaction = Dexie.currentTransaction;
            await plain.rows.get(1);
            await nativeHelper();
            zoneAfterHelper = Dexie.currentTransaction === transaction;
            return plain.rows.get(1);
        });
        // ONE encrypted read, started in the same tick as the scope above.
        const read = encrypted.friends.get(1);

        await expect(scope).resolves.toEqual({ id: 1 });
        expect(zoneAfterHelper).toBe(true);
        await expect(read).resolves.toMatchObject({ name: 'Camilla', street: 'East 13:th Street' });
    });
});
