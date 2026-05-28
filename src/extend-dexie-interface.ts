import { IndexableType, TableProp } from 'dexie';
// import {
//   DBRealm,
//   DBRealmMember,
//   DBRealmRole,
// } from 'dexie-cloud-common';
// import { Member } from './db/entities/Member';
// import { Role } from './db/entities/Role';
// import { EntityCommon } from './db/entities/EntityCommon';

import { DexieEncryptionAPI } from './DexieEncryptionAPI';
// import { DexieCloudTable } from './DexieCloudTable';
// import { NewIdOptions } from './types/NewIdOptions';

type Optional<T, Props extends keyof T> = Omit<T, Props> & Partial<T>;

//
// Extend Dexie interface
//
declare module 'dexie' {
  interface Dexie {
    encryption: DexieEncryptionAPI;
    // realms: Table<DBRealm, string, Optional<DBRealm, 'realmId' | 'owner'>>;
    // members: Table<DBRealmMember, string, Optional<DBRealmMember, 'id' | 'owner'>>;
    // roles: Table<DBRealmRole, [string, string], Optional<DBRealmRole, 'owner'>>;
  }

  interface Table {
    // newId(options: NewIdOptions): string;
    // idPrefix(): string;
  }

  interface DexieConstructor {
    Encryption: {
      (db: Dexie): void;
      version: string;
    };
  }
}
