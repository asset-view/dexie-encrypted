/** @type {import('jest').Config} */
module.exports = async () => {
    return {
        preset: 'ts-jest',
        testEnvironment: 'jsdom',
        clearMocks: true,
        moduleNameMapper: {
            '^dexie$': require.resolve('dexie'),
        },
    };
};
