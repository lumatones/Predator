import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/__tests__/**/*.test.ts'],
    // 10-second timeout per test (DB mocking is instant)
    testTimeout: 10000,
  },
})
