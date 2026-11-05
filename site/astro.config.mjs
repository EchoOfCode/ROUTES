import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  devToolbar: {
    enabled: false,
  },
  integrations: [
    react(),
    tailwind({
      applyBaseStyles: false,
    }),
  ],
  vite: {
    resolve: {
      preserveSymlinks: true,
    },
    server: {
      fs: {
        allow: [
          'D:/routes_web',
          'D:/ROUTES',
        ],
      },
    },
  },
});

