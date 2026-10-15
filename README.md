# VMM Diwali Gifting Enquiry – App v6 (GitHub Pages + Supabase)

Same app, same screens and same roles as v5. Only the database changed: **Firebase Firestore → Supabase (Postgres, Mumbai)**.
Login is still **code + 6-digit PIN** (default PIN `456987`, forced change on first login, Forgot PIN → Central Ops Admin reset).
Each store sees only its own data – enforced inside the database, not just in the app.

## Folder

| Path | What |
|---|---|
| `index.html` | Whole app. Supabase URL + publishable key are already filled in at the top. |
| `products/P001–P328.jpg` | One photo per catalogue product (picker, enquiry, WhatsApp). |
| `catalogue/p03–p45.jpg` | Full catalogue pages (fallback when a product has no own photo). |
| `vmm-logo.png` | Logo. |
| `supabase/setup.sql` | Run once in Supabase › SQL Editor. Creates the tables, access rules and login functions. |

Not in this repo (upload from the Admin screen on your PC): `VMM_Store_Master.csv`, `Products.csv`, `Escalation_Matrix.csv`.
The escalation matrix has staff phone numbers, so it must not go into a public repo.

## Set-up (≈15 min)

1. **Supabase** › SQL Editor › New query › paste all of `supabase/setup.sql` › **Run** → "Success. No rows returned".
   (It also removes the test tables made during the first set-up steps.)
2. **GitHub Pages** › repo `Gifting_Enquiry` › Settings › Pages › branch `main`, folder `/ (root)`.
3. **First login = Admin**: open the site, enter *your* employee code + PIN `456987` → set your own PIN → Admin screen → **Make this login Admin**.
   Do this right after step 1 – the first login on an empty database becomes Admin.
4. On the Admin screen upload **Store master** (`VMM_Store_Master.csv` – also activates logins for all stores, AMs and ZFMs), then **Products.csv**, then **Escalation_Matrix.csv**.
   Set GPS radius, HO codes (use codes that are **not** store codes), other Admin codes → **Save settings**.
5. Go live: stores log in with **store code** (within the GPS radius), AMs with **AM Code**, zones with `ZFM-<NAME>`, HO with the codes you listed.

## How security works

- The browser only has the **publishable key**. It cannot read or write any table directly (Row Level Security on, no policies).
- Every read / write goes through database functions (`dge_get`, `dge_query`, `dge_write`) that apply the same rules as v5:
  store → own store only, AM → own stores, ZFM / HO / Admin → all; enquiry fields that can change after capture are fixed; masters and settings → Admin only.
- PINs are stored as bcrypt hashes. 5 wrong PINs lock that login for 15 minutes.
- Login = random session token (valid 30 days); only its SHA-256 hash is stored.
- **PIN reset / lost phone**: Admin › PIN resets › Reset. The old phone loses access on its next request; the user logs in with `456987` and sets a new PIN.
- **Never** put the `service_role` / secret key in `index.html` or GitHub.

### Limits you should know
- `456987` is shared. Until a store sets its own PIN, anyone with the link and that store code can claim it first. Ask every store to log in on day 1.
- GPS fence is checked in the app, not by the database.
- Store list, product master, escalation contacts and the code list are readable on the login screen (no customer data).
- A person trying wrong PINs can lock a code for 15 minutes (Admin can reset).

## Supabase free plan – what to watch

- Database **500 MB** ≈ 1.5–2 lakh enquiries. Downloads **5 GB / month**. Store quotas in Admin settings keep usage down.
- Check **Supabase › Reports › Database** during the season. If it nears 500 MB, move to the Pro plan (about $25/month).
- Free projects pause after 7 days with no use – not an issue during the season, but open the app once a week before it starts.

## Testing checklist

1. Wrong PIN refused; default PIN forces a new PIN; Forgot PIN → Admin sees request → Reset → old PIN refused, default works.
2. Store login outside the radius refused; inside works; Test mode skips GPS.
3. Capture Individual / Corporate / Bulk → HOT tag at ≥20 units or ≥₹25k.
4. Follow-up, escalate, convert, lost; AM reopens.
5. Another store opening this enquiry's link gets "Not allowed".
6. HO dashboard → tap AM → store leaderboard; hot / overdue lists; export.
