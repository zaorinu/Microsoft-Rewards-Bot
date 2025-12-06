# Error Reporting API

## What it does
Accepts structured error reports and forwards them to Discord in a clean format. Submissions require a shared secret header so random users cannot spam your webhook.

## How to use
- Set `DISCORD_WEBHOOK_URL` and `ERROR_REPORT_TOKEN` in your environment (e.g., Vercel project settings → Environment Variables).
- Send a POST request to `/api/report-error` with header `x-error-report-token: <your token>` and JSON that includes at least `error`.
- Optional fields: `summary`, `type`, `metadata` (object), `environment` (string or object with `name`).

## Example
```bash
curl -X POST https://your-deployment.vercel.app/api/report-error \
  -H "Content-Type: application/json" \
  -H "x-error-report-token: YOUR_TOKEN" \
  -d '{"error":"Search job failed","type":"search","metadata":{"account":"user@contoso.com"}}'
```

---
**[← Back to Documentation](index.md)**
