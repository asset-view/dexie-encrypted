import { CryptoSettings2 } from "./types";
/** The API of db.cloud, where `db` is an instance of Dexie with dexie-cloud-addon active.
 */
export interface LoginHints {
    email?: string;
    userId?: string;
    grant_type?: 'demo' | 'otp';
    otpId?: string;
    otp?: string;
}
export interface DexieEncryptionAPI {
    version: string;
    tableSettings: CryptoSettings2;
}
