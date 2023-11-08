import { defineConfig } from 'rollup';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';

const inputs = ['src/index.ts'];
const externals = [
    'dexie',
    '@stablelib/utf8',
    'tweetnacl',
    'typeson',
    'typeson-registry',
    'typeson-registry/dist/presets/builtin',
];

export default defineConfig([
    // * CJS Bundle -------------------------------------------------------------
    {
        input: inputs,
        external: externals,
        output: [
            {
                file: 'dist/dexie-encrypted.cjs',
                format: 'cjs', // CS module
                sourcemap: true,
            },
        ],
        plugins: [
            typescript({ compilerOptions: { module: 'ES2022' } }),
            // commonjs(),
            // resolve(),
        ],
    },
    // * ESM Bundle -------------------------------------------------------------
    {
        input: inputs,
        external: externals,
        output: [
            {
                file: 'dist/dexie-encrypted.mjs',
                format: 'esm', // ES module individual files
                sourcemap: true,
            },
        ],
        plugins: [
            typescript({ compilerOptions: { module: 'ES2022' } }),
            // commonjs(),
            // resolve(),
        ],
    },
]);
