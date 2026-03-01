/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["**/tests/**/*.test.ts"],
  moduleFileExtensions: ["ts", "js", "json"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        tsconfig: {
          // Use CommonJS for Jest (avoids ESM transform complexity)
          module: "CommonJS",
          moduleResolution: "node",
          esModuleInterop: true,
        },
      },
    ],
  },
  // Map .js imports to .ts source for Jest (TypeScript source-level testing)
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  collectCoverageFrom: ["src/**/*.ts", "!src/**/*.d.ts"],
};
