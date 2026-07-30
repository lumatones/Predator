// ESLint v9 flat config — ported from the previous `.eslintrc.json`.
// Uses `@eslint/js` (eslint:recommended) + `typescript-eslint` recommended,
// with our own rule overrides and an ignores block matching the prior pattern.

import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import globals from 'globals'

export default tseslint.config(
  {
    // Match the ignorePatterns that used to live in .eslintrc.json
    ignores: [
      'dist/**',
      'dist-electron/**',
      'release/**',
      'node_modules/**',
      'installer/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      // electron/** runs in node; src/** runs in the renderer (browser) — provide both
      globals: {
        ...globals.node,
        ...globals.browser,
      },
      sourceType: 'module',
    },
    rules: {
      // Custom overrides (same as the old config)
      'no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'none' }],
      'prefer-const': 'warn',
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-control-regex': 'off',
    },
  },
)
