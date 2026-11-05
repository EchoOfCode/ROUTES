/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        acid: '#FF3333', // Main Red theme
        cyan: '#1CE3D6', // Electric Cyan
        paper: '#F2EFE9',
        kraft: '#9E9A8E',
        kraftDark: '#7C786D',
        xerox: '#181818',
        newsprint: '#DCD8CF',
      },
      fontFamily: {
        typewriter: ['"Special Elite"', 'monospace'],
        mono: ['"Space Mono"', 'monospace'],
        scrawl: ['"Rock Salt"', 'cursive'],
        marker: ['"Permanent Marker"', 'cursive'],
        abstract: ['"Unbounded"', 'sans-serif'],
        syne: ['"Syne"', 'sans-serif'],
      },
    },
  },
  plugins: [],
};

