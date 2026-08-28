# OMNI Trust Interceptor landing page

Standalone frontend for the OMNI API repository. The page is intentionally isolated under `site/` so it can be deployed independently without changing the Bun/Express backend.

## Local development

```bash
npm install
npm run dev
```

The Vite dev server binds to `127.0.0.1:4173` by default.

## Stack

- React 19.2.8
- Vite 8.2.2
- TypeScript 7.0.2
- GSAP 3.15.0 + `@gsap/react` 2.1.2

The interface supports light and dark themes, an orbital canvas field, reduced-motion fallback, pinned ScrollTrigger chapters, and responsive layouts.
