import type { Plugin } from 'vite'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import mockAdminApi from './vite-mock-api'

export default defineConfig(({ mode }) => {
  const isDev = mode === 'development'
  return {
    plugins: [react(), isDev ? mockAdminApi() : null].filter((p): p is Plugin => Boolean(p)),
    server: {
      host: true,
      port: 5173,
      proxy: isDev
        ? undefined
        : {
            '/api': {
              target: 'http://127.0.0.1:3001',
              changeOrigin: true,
            },
          },
    },
  }
})
