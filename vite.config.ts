import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// REQ-NF-005: 모든 분석은 브라우저(로컬)에서 수행 → 데이터 외부 유출 없음.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    open: true,
  },
});
