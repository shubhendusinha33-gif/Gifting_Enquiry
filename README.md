# VMM Diwali Gifting Enquiry – App v7 (GitHub Pages + Supabase)

Same app, same screens and same roles as v5. Only the database changed: **Firebase Firestore → Supabase (Postgres, Mumbai)**.
Login is still **code + 6-digit PIN** (default PIN `456987`, forced change on first login).

**New in v7**
- **Forgot PIN without Admin**: at first login everyone registers a mobile number. Forgot PIN → enter registered mobile + new PIN → logged in. Stores must be within the GPS radius (unless Test mode is ON). Admin reset stays only as a fallback (no registered mobile).
- **Unknown code**: "Store not in master, please contact Shubhendu Sinha".
- **Session time-out**: Admin settings › *Log out after no activity (minutes)* and *Longest session (minutes)*. Enforced on the phone and in the database.
- **Login & PIN log** (Admin › Login & PIN log): every login, wrong PIN, lock, PIN change, mobile registration, Forgot-PIN reset, Admin reset, logout and time-out, with designation and distance from the store. Filter, CSV export, kept 180 days.
- **Test mode ON** skips the GPS fence for login and Forgot PIN (shown on the login screen and in the log).
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
- **Forgot PIN**: registered mobile + new PIN. All old phones of that code lose access immediately. 5 wrong mobiles lock Forgot PIN for 30 minutes.
- **Registered mobiles** are stored only as bcrypt hashes (Admin sees the last 4 digits in the log).
- **Lost phone / staff left**: Admin › PIN resets › Reset. The old phone loses access on its next request; the registered mobile is cleared, so the next person logs in with `456987` and registers their own mobile.
- **Never** put the `service_role` / secret key in `index.html` or GitHub.

### Limits you should know
- `456987` is shared. Until a store sets its own PIN, anyone with the link and that store code can claim it first. Ask every store to log in on day 1.
- GPS fence is checked in the app, not by the database.
- Store list, product master, escalation contacts and the code list are readable on the login screen (no customer data).
- A person trying wrong PINs can lock a code for 15 minutes (Admin can reset).
- Anyone who knows a store's code, registered mobile and is at the store can reset its PIN – keep the registered mobile with the SM.
- Logins refused by the GPS fence are stopped on the phone, so they do not appear in the log.

## Supabase free plan – what to watch

- Database **500 MB** ≈ 1.5–2 lakh enquiries. Downloads **5 GB / month**. Store quotas in Admin settings keep usage down.
- Check **Supabase › Reports › Database** during the season. If it nears 500 MB, move to the Pro plan (about $25/month).
- Free projects pause after 7 days with no use – not an issue during the season, but open the app once a week before it starts.

## Testing checklist

1. Wrong PIN refused; default PIN forces a new PIN + mobile; Forgot PIN with registered mobile → new PIN works, old PIN and old phone refused; wrong mobile refused.
1a. Unknown code → "Store not in master, please contact Shubhendu Sinha".
1b. Set idle time-out to 5 min, leave the phone 6 min → next tap logs out with the reason; entry appears in the Login & PIN log.
2. Store login outside the radius refused; inside works; Test mode skips GPS.
3. Capture Individual / Corporate / Bulk → HOT tag at ≥20 units or ≥₹25k.
4. Follow-up, escalate, convert, lost; AM reopens.
5. Another store opening this enquiry's link gets "Not allowed".
6. HO dashboard → tap AM → store leaderboard; hot / overdue lists; export.
