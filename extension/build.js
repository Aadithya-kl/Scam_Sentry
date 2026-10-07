const esbuild = require('esbuild');
const tailwindcss = require('tailwindcss');
const autoprefixer = require('autoprefixer');
const postcss = require('postcss');
const fs = require('fs');

async function build() {
  // Build React popup
  await esbuild.build({
    entryPoints: ['src/popup.tsx', 'src/background.ts'],
    bundle: true,
    outdir: '.',
    minify: true,
    format: 'iife',
    target: ['es2020'],
    define: {
      'process.env.API_BASE_URL': JSON.stringify(process.env.API_BASE_URL || "http://localhost:8000"),
      'process.env.DASHBOARD_URL': JSON.stringify(process.env.DASHBOARD_URL || "http://localhost:3000"),
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || "development")
    }
  });

  // Build Tailwind CSS
  const cssInput = fs.readFileSync('src/styles.css', 'utf8');
  const result = await postcss([
    tailwindcss({
      content: ['./src/**/*.{html,ts,tsx}', './popup.html'],
      theme: {
        extend: {
          colors: {
            bgBase: '#08090C',
            bgSurface: '#101218',
            bgElevated: '#161922',
            textPrimary: '#F4F5F7',
            textSecondary: '#969BA8',
            textMuted: '#5E6370',
            accentCyan: '#00F0FF',
            accentLime: '#D9FF00',
            statusSafe: '#00F0FF',
            statusSuspicious: '#FFB800',
            statusSpam: '#FF7B00',
            statusScam: '#FF3366',
          },
          fontFamily: {
            sans: ['Inter', 'system-ui', 'sans-serif'],
            mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
          }
        }
      }
    }),
    autoprefixer
  ]).process(cssInput, { from: 'src/styles.css', to: 'styles.css' });

  fs.writeFileSync('styles.css', result.css);
  console.log('Build complete');
}

build().catch(console.error);
