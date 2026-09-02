# frontend/ — analyst dashboard (Next.js)

Owner: frontend engineer, with UI/UX + QA.

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev        # http://localhost:3000
```

The backend must be running on `http://localhost:8000` (see the root README).

## Layout

| Folder | Purpose |
| --- | --- |
| `app/` | App Router pages: `/` (dashboard shell). Planned: `/login`, `/alerts`, `/alerts/[id]`, `/upload`, `/admin`. |
| `components/` | Reusable UI (`SystemStatus`, alert cards, charts). |
| `lib/` | API client (`api.ts`) typed against `docs/api/api-contracts.md`. |
| `public/` | Static assets. |

## Rules

- Rely on `risk_score`, `risk_level`, `created_at`, and `status` from the API, never on ID order.
- Every screen needs empty, loading, and error states (backend failure shows a banner, never a blank page).
- Keep it simple: one dashboard, one alert detail page, one replay flow. No theming battles.
