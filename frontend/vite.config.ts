import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': 'http://localhost:8000' } },
  build: { rollupOptions: { output: { manualChunks: { react: ['react', 'react-dom', 'react-router-dom'] } } } },
})
