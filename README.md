# VMM Diwali Gifting Enquiry – App v8 (GitHub Pages + Supabase)

Same app, same screens and same roles as v5. Only the database changed: **Firebase Firestore → Supabase (Postgres, Mumbai)**.
Login is still **code + 6-digit PIN** (default PIN `456987`, forced change on first login).

**New in v8**
- **Store login screen shows only "Store code"** (+ designation). AM / ZFM / HO / Admin tap *AM / ZFM / HO login →* to switch to Employee code. A wrong kind of code is refused with a clear message.
- **Edit with reason**: open enquiries can be edited (customer and products). A reason is required; it shows in the enquiry journey and in **Admin › Edit & delete log** (before → after). The database refuses any customer/product change without a reason.
- **Delete = Admin only, with reason**: dashboards are corrected, phones drop the enquiry on their next refresh, and the full record is kept in the Edit & delete log. Nobody else can delete (also blocked in the database).
- **Admin › Sessions**: who is logged in now (code, role, login time, last activity, last save, designation, distance, device) and who logged in today. **Force logout** one phone or every phone of a code.
- **Time-outs** (Admin settings, minutes): idle logout default **15**; **store no-save logout** default **10** (a store login that saves no enquiry / follow-up for 10 min is logged out; warning banner in the last 2 min; 0 = off); longest session unchanged.
- **Customer WhatsApp**: ready, editable message to the customer with products, qty and value; product photo attached through the phone's share list. **No links** in any message (customer or buyer).
- **Buyer escalation**: "Customer asked for discount %" goes into the ready message (with the per-unit price after discount for a single product).
- **Search / filter on every page**: search on store home, HO dashboard (store code, AM, enquiry ID, mobile) and list; a filter box above every table.
- **Snapshot camera** on dashboard panels and tables: HD picture squeezed to ≤ 64 KB, copied to the clipboard (paste in WhatsApp Web / mail / Excel), plus Share and Download. Admin chooses who gets it (Admin only / Admin + HO / everyone). Nothing is uploaded.
- **Lighter login hashing** (bcrypt cost 6) and fewer housekeeping deletes, so a morning login rush costs less database CPU.

**v7**
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
| `supabase/setup.sql` | Run once in Supabase › SQL Editor. Creates the tables, access rules and login functions. Safe to run again after every update. |
| `vendor/` | html2canvas, pako, UPNG – used only by the snapshot camera, loaded on first tap (licences in `vendor/LICENSES.txt`). |

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
- A deleted enquiry can be restored only by SQL from the copy kept in `dge_audit` (ask Central Ops).
- Copying an image to the clipboard works in Chrome / Edge / Safari; on Android, WhatsApp cannot paste images – use **Share**.

## Load (tested on a local copy, 2 CPU cores, 40,000 enquiries, 5,000 open sessions)

| Call | What triggers it | Per second (40 at once) |
|---|---|---|
| App open (session check + settings) | opening the app | ~3,900 |
| Refresh changed enquiries | every 5 min while used | ~2,200 |
| Full store download | first login on a phone | ~570 |
| Save enquiry (+ dashboard counters) | Save | ~630 |
| Login (PIN check) | Enter | ~370 |

5,000 users each doing something every 30 seconds is about 170 database calls a second – well inside these numbers. Supabase's free plan runs on a **shared** CPU, so expect less than this; the numbers above are not a guarantee for the free plan.

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
7. v8: store login shows only Store code; AM code there is refused; switch link works.
8. v8: edit an enquiry (reason asked) → journey + Edit & delete log; Admin delete (reason) → gone from store list and dashboards.
9. v8: Admin › Sessions shows the store; Force logout → store sees "Logged out by Admin".
10. v8: store does nothing for the no-save minutes → warning, then logged out.
11. v8: customer and buyer WhatsApp have no links; discount % appears in the buyer message.
12. v8: camera on a dashboard panel → "Copied (xx KB)", ≤ 64 KB; filter box above each table.
