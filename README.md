# TRACORITHM (unified)

Single-page dashboard + Node.js/Express + PostgreSQL. Roles: admin, inspector, manufacturer.

## Run locally
1. Install Node 18+ and PostgreSQL. Create an empty database: `createdb tracorithm`
2. `cp .env.example .env` and fill it in (DATABASE_URL, SESSION_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD).
3. `npm install`
4. Load the variables and start: `export $(grep -v '^#' .env | xargs) && npm start`
5. Open http://localhost:5000 and sign in as the admin. In **Users**, create an inspector and a manufacturer account.
   (Camera needs https or localhost.)

Tables are created automatically on first start. The first admin is created from ADMIN_USERNAME / ADMIN_PASSWORD only when the users table is empty.

## Deploy on Render
- New Web Service from your GitHub repo, build `npm install`, start `npm start`.
- Add env vars: DATABASE_URL (your Render PostgreSQL internal URL), SESSION_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD, NODE_ENV=production.
- Use a NEW database or new tables: this app creates its own tables and does not read the old TRACORITHM schema.

## QR codes
QR format: `https://<your-site>/f/<FITTING-ID>`. Opening it asks for login, then shows that fitting.
Old pages /install.html, /railclip.html, /pandrol.html redirect to /f/TRC-FP-001, /f/TRC-RC-003, /f/TRC-PC-002.
Register those three IDs (same component names) so the redirects find records.

## AI model
Files in `public/model/` are your Teachable Machine export (4 classes: Fish Plate / Rail Clip, Good / Damaged). No Pandrol Clip class exists yet.
