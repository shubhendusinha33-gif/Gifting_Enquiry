-- =====================================================================
-- VMM Diwali Gifting Enquiry – Supabase backend (v8)
-- Same app and screens. Firestore is replaced by one Postgres table of
-- documents. Every read and write goes through the functions below,
-- which apply the access rules. Browsers can never touch the tables
-- directly (RLS on, no policies).
--
-- v7 adds: self-service Forgot PIN (registered mobile), idle / maximum
-- session time-out set by Admin in minutes, and a login / PIN log.
-- v8 adds: Admin-only enquiry delete with reason, edit with reason
-- (both in the Edit & delete log), Admin Sessions tab with force logout,
-- store "no save" time-out, idle default 15 min, lighter login hashing.
--
-- Run this whole file in Supabase › SQL Editor › New query › Run.
-- Safe to run again: it keeps all data and only replaces functions.
-- =====================================================================

-- ---------- 0. Remove the test objects created during first set-up ----------
drop function if exists public.save_enquiry(text, jsonb);
drop function if exists public.store_login(text, text);
drop function if exists public.session_store(text);
drop function if exists public.verify_store_pin(text, text);
drop table if exists public.store_sessions;
drop table if exists public.follow_ups;
drop table if exists public.audit_log;
drop table if exists public.enquiry_items;
drop table if exists public.enquiries;
drop table if exists public.stores;
drop sequence if exists public.enquiry_seq;
-- v6 signatures that changed in v7
drop function if exists public.dge_sign_in(text, text);
drop function if exists public.dge_create_login(text, text);
drop function if exists public.dge_sign_out(text);
-- v7 signature that changed in v8
drop function if exists public.dge_new_session(text, uuid);

create extension if not exists pgcrypto with schema extensions;

-- ---------- 1. Tables ----------
create table if not exists public.dge_docs (
  col        text        not null,
  id         text        not null,
  data       jsonb       not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (col, id)
);

create table if not exists public.dge_logins (
  email          text        primary key,            -- <code>.<k>@vmm-diwali.app
  uid            uuid        not null default gen_random_uuid(),
  pin_hash       text        not null,               -- bcrypt, never returned
  failed         int         not null default 0,
  locked_until   timestamptz,
  created_at     timestamptz not null default now(),
  pin_changed_at timestamptz
);

create table if not exists public.dge_sessions (
  token_hash text        primary key,                -- sha256 of the token
  email      text        not null references public.dge_logins(email) on delete cascade,
  uid        uuid        not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
alter table public.dge_sessions add column if not exists last_seen timestamptz not null default now();
-- v8: who is logged in (Admin › Sessions), last save (store "no save" time-out), Admin force logout
alter table public.dge_sessions add column if not exists code       text;
alter table public.dge_sessions add column if not exists role       text;
alter table public.dge_sessions add column if not exists meta       jsonb;
alter table public.dge_sessions add column if not exists last_save  timestamptz not null default now();
alter table public.dge_sessions add column if not exists end_reason text;

-- v8: enquiry edits and Admin deletes (with reason)
create table if not exists public.dge_audit (
  id         bigserial   primary key,
  at         timestamptz not null default now(),
  code       text        not null,      -- who did it
  action     text        not null,      -- EDIT | DELETE
  enq_id     text        not null,
  store_code text,
  reason     text,
  detail     jsonb
);

-- registered mobile per code, used for self-service Forgot PIN (bcrypt hash only)
create table if not exists public.dge_recovery (
  code         text        primary key,
  mobile_hash  text        not null,
  last4        text,
  set_at       timestamptz not null default now(),
  failed       int         not null default 0,
  locked_until timestamptz
);

-- login / PIN events shown to Admin
create table if not exists public.dge_auth_log (
  id     bigserial   primary key,
  at     timestamptz not null default now(),
  code   text        not null,
  event  text        not null,
  ok     boolean     not null,
  detail text,
  meta   jsonb
);

alter table public.dge_docs     enable row level security;
alter table public.dge_logins   enable row level security;
alter table public.dge_sessions enable row level security;
alter table public.dge_recovery enable row level security;
alter table public.dge_auth_log enable row level security;
alter table public.dge_audit    enable row level security;
revoke all on public.dge_docs, public.dge_logins, public.dge_sessions, public.dge_recovery, public.dge_auth_log, public.dge_audit
  from public, anon, authenticated;
revoke all on sequence public.dge_auth_log_id_seq from public, anon, authenticated;
revoke all on sequence public.dge_audit_id_seq from public, anon, authenticated;

create index if not exists dge_enq_store_upd on public.dge_docs ((data->'storeCode'), (data->'updatedAt')) where col = 'enquiries';
create index if not exists dge_enq_am_upd    on public.dge_docs ((data->'amCode'), (data->'updatedAt'))    where col = 'enquiries';
create index if not exists dge_enq_mobile    on public.dge_docs ((data->'mobile'))                         where col = 'enquiries';
create index if not exists dge_enq_status    on public.dge_docs ((data->'status'))                         where col = 'enquiries';
create index if not exists dge_enq_zfm       on public.dge_docs ((data->'zfm'))                            where col = 'enquiries';
create index if not exists dge_stats_date    on public.dge_docs ((data->'date'))                           where col = 'stats';
create index if not exists dge_sessions_exp  on public.dge_sessions (expires_at);
create index if not exists dge_sessions_mail on public.dge_sessions (email);
create index if not exists dge_log_at        on public.dge_auth_log (at desc);
create index if not exists dge_log_code      on public.dge_auth_log (code, at desc);
create index if not exists dge_sessions_seen on public.dge_sessions (last_seen);
create index if not exists dge_audit_at      on public.dge_audit (at desc);
create index if not exists dge_audit_store   on public.dge_audit (store_code, at desc);

-- ---------- 2. Small helpers ----------
create or replace function public.dge_str(v jsonb, n int) returns boolean
language sql immutable set search_path = public as $$
  select coalesce(jsonb_typeof(v) = 'string' and length(v #>> '{}') <= n, false);
$$;

create or replace function public.dge_num(v jsonb, lo numeric, hi numeric) returns boolean
language plpgsql immutable set search_path = public as $$
begin
  if v is null or jsonb_typeof(v) <> 'number' then return false; end if;
  return (v #>> '{}')::numeric between lo and hi;
end $$;

-- a whole-number setting from settings/app, with default and limits
create or replace function public.dge_set_int(st jsonb, k text, def int, lo int, hi int) returns int
language plpgsql immutable set search_path = public as $$
declare v numeric;
begin
  if st is null or jsonb_typeof(st -> k) is distinct from 'number' then return def; end if;
  v := (st ->> k)::numeric;
  return least(greatest(round(v)::int, lo), hi);
end $$;

create or replace function public.dge_changed(o jsonb, n jsonb) returns text[]
language sql immutable set search_path = public as $$
  select coalesce(array_agg(k), '{}'::text[]) from (
    select jsonb_object_keys(coalesce(o, '{}'::jsonb)) as k
    union
    select jsonb_object_keys(coalesce(n, '{}'::jsonb))
  ) x where (o -> k) is distinct from (n -> k);
$$;

create or replace function public.dge_keys(d jsonb) returns text[]
language sql immutable set search_path = public as $$
  select coalesce(array_agg(k), '{}'::text[]) from jsonb_object_keys(coalesce(d, '{}'::jsonb)) k;
$$;

create or replace function public.dge_weak_pin(p text) returns boolean
language sql immutable set search_path = public as $$
  select coalesce(p, '') !~ '^[0-9]{6}$' or p = '456987' or p ~ '^(.)\1{5}$'
      or p in ('123456', '654321', '012345', '098765');
$$;

-- only a few short, harmless fields from the phone go into the log
create or replace function public.dge_clean_meta(m jsonb) returns jsonb
language sql immutable set search_path = public as $$
  select case when m is null or jsonb_typeof(m) <> 'object' then null else jsonb_strip_nulls(jsonb_build_object(
    'desig', left(m ->> 'desig', 12),
    'km',    case when jsonb_typeof(m -> 'km') = 'number' then m -> 'km' end,
    'test',  case when jsonb_typeof(m -> 'test') = 'boolean' then m -> 'test' end,
    'ua',    left(m ->> 'ua', 120))) end;
$$;

create or replace function public.dge_log(p_code text, p_event text, p_ok boolean, p_detail text, p_meta jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.dge_auth_log (code, event, ok, detail, meta)
  values (left(upper(coalesce(p_code, '?')), 30), p_event, p_ok, left(p_detail, 200), public.dge_clean_meta(p_meta));
  if random() < 0.01 then
    delete from public.dge_auth_log where at < now() - interval '180 days';
  end if;
end $$;

create or replace function public.dge_now_ist() returns text
language sql stable set search_path = public as $$
  select to_char(now() at time zone 'Asia/Kolkata', 'YYYY-MM-DD"T"HH24:MI:SS');
$$;

-- v8: before / after values for the Edit & delete log (mobile masked, products as a summary)
create or replace function public.dge_audit_view(d jsonb, f text[]) returns jsonb
language sql immutable set search_path = public as $$
  select coalesce(jsonb_object_agg(k, case
            when k = 'mobile' then to_jsonb(left(d ->> 'mobile', 2) || '•••••' || right(d ->> 'mobile', 3))
            when k = 'lines'  then to_jsonb(d ->> 'productSummary')
            else d -> k end), '{}'::jsonb)
    from unnest(coalesce(f, '{}'::text[])) k
   where d ? k;
$$;

-- Apply a write the way Firestore does.
--   {__inc:n}  -> add n      {__union:x} -> append x if missing
--   {__now:1}  -> server time in ms
--   deep=true  -> nested objects are merged (set with merge)
--   deep=false -> nested objects replace the field (update)
create or replace function public.dge_apply(old jsonb, upd jsonb, deep boolean, now_ms bigint) returns jsonb
language plpgsql immutable set search_path = public as $$
declare
  r   jsonb := coalesce(old, '{}'::jsonb);
  k   text;
  v   jsonb;
  cur jsonb;
  arr jsonb;
begin
  if jsonb_typeof(r) <> 'object' then r := '{}'::jsonb; end if;
  if upd is null or jsonb_typeof(upd) <> 'object' then return r; end if;
  for k, v in select * from jsonb_each(upd) loop
    cur := r -> k;
    if jsonb_typeof(v) = 'object' and v ? '__inc' then
      r := jsonb_set(r, array[k], to_jsonb(
             coalesce(case when jsonb_typeof(cur) = 'number' then (cur #>> '{}')::numeric end, 0)
             + coalesce(case when jsonb_typeof(v -> '__inc') = 'number' then (v ->> '__inc')::numeric end, 0)));
    elsif jsonb_typeof(v) = 'object' and v ? '__union' then
      arr := case when jsonb_typeof(cur) = 'array' then cur else '[]'::jsonb end;
      if not exists (select 1 from jsonb_array_elements(arr) e where e = v -> '__union') then
        arr := arr || jsonb_build_array(v -> '__union');
      end if;
      r := jsonb_set(r, array[k], arr);
    elsif jsonb_typeof(v) = 'object' and v ? '__now' then
      r := jsonb_set(r, array[k], to_jsonb(now_ms));
    elsif jsonb_typeof(v) = 'object' then
      r := jsonb_set(r, array[k], public.dge_apply(
             case when deep and jsonb_typeof(cur) = 'object' then cur else '{}'::jsonb end, v, true, now_ms));
    else
      r := jsonb_set(r, array[k], v);
    end if;
  end loop;
  return r;
end $$;

-- Who is calling: resolves the session token to code, role and rights.
-- Ends the session (and logs it) when it is idle too long, too old, or the PIN was reset.
create or replace function public.dge_ctx(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_th      text;
  v_email   text;
  v_uid     uuid;
  v_created timestamptz;
  v_last    timestamptz;
  v_exp     timestamptz;
  v_save    timestamptz;
  v_srole   text;
  v_end     text;
  v_nosave  int;
  v_local   text;
  v_code    text := '';
  v_k       text := '';
  u         jsonb;
  st        jsonb;
  v_bound   boolean := false;
  v_role    text := '';
  v_admin   boolean := false;
  v_expired boolean := false;
  v_why     text := '';
  v_idle    int;
  v_max     int;
begin
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  if p_token is not null and p_token <> '' then
    if length(p_token) between 32 and 128 then
      v_th := encode(extensions.digest(p_token, 'sha256'), 'hex');
      select s.email, s.uid, s.created_at, s.last_seen, s.expires_at, s.last_save, s.role, s.end_reason
        into v_email, v_uid, v_created, v_last, v_exp, v_save, v_srole, v_end
        from public.dge_sessions s where s.token_hash = v_th;
    end if;
    if v_email is null then
      v_expired := true;
      v_why := 'Session ended – please log in again.';
    else
      v_local := split_part(v_email, '@', 1);
      v_code  := upper(split_part(v_local, '.', 1));
      v_k     := split_part(v_local, '.', 2);
      v_idle  := public.dge_set_int(st, 'idleMins', 15, 5, 1440);
      v_max   := public.dge_set_int(st, 'sessionMins', 720, 30, 43200);
      v_nosave := public.dge_set_int(st, 'noSaveMins', 10, 0, 720);
      select data into u from public.dge_docs where col = 'users' and id = v_code;
      if v_end is not null then
        v_why := v_end;                                        -- Admin force logout (already logged)
      elsif v_exp < now() or v_created < now() - make_interval(mins => v_max) then
        v_why := 'Session time limit reached (' || v_max || ' min) – please log in again.';
      elsif v_last < now() - make_interval(mins => v_idle) then
        v_why := 'Logged out after ' || v_idle || ' min with no activity – please log in again.';
      elsif coalesce(v_srole, u ->> 'role', '') = 'STORE' and v_nosave > 0
            and coalesce(v_save, v_created) < now() - make_interval(mins => v_nosave) then
        v_why := 'Logged out – no enquiry or follow-up saved in ' || v_nosave || ' min. Please log in again.';
      elsif u is not null and coalesce(u ->> 'uid', '') <> '' and u ->> 'uid' <> v_uid::text then
        v_why := 'Your PIN was reset – please log in again.';
      end if;
      if v_why <> '' then
        delete from public.dge_sessions where token_hash = v_th;
        if v_end is null then perform public.dge_log(v_code, 'SESSION_END', true, v_why, null); end if;
        v_expired := true; v_email := null; v_uid := null; v_code := ''; v_k := ''; u := null;
      elsif v_last < now() - interval '1 minute' then
        update public.dge_sessions set last_seen = now() where token_hash = v_th;
      end if;
    end if;
  end if;
  if v_email is not null then
    v_bound := u is not null and coalesce(u ->> 'uid', '') = v_uid::text;
    if v_bound then v_role := coalesce(u ->> 'role', ''); end if;
    v_admin := st is not null and (
                 (jsonb_typeof(st -> 'adminUids') = 'array' and (st -> 'adminUids') ? v_uid::text)
                 or (v_bound and v_role = 'ADMIN'));
  end if;
  return jsonb_build_object(
    'email', v_email, 'uid', v_uid, 'code', v_code, 'k', v_k,
    'auth',  v_email is not null,
    'bound', v_bound, 'role', v_role, 'admin', v_admin,
    'mgmt',  v_bound and v_role in ('ZFM', 'HO', 'ADMIN'),
    'th',    case when v_email is not null then v_th end,
    'expired', v_expired, 'why', v_why);
end $$;

create or replace function public.dge_can_see(c jsonb, d jsonb) returns boolean
language sql immutable set search_path = public as $$
  select coalesce((c ->> 'mgmt')::boolean, false)
      or (coalesce((c ->> 'bound')::boolean, false) and (
            (c ->> 'role' = 'STORE' and d ->> 'storeCode' = c ->> 'code')
         or (c ->> 'role' = 'AM'    and d ->> 'amCode'    = c ->> 'code')));
$$;

create or replace function public.dge_valid_enq(d jsonb) returns boolean
language plpgsql immutable set search_path = public as $$
begin
  if not public.dge_str(d -> 'storeCode', 12) or coalesce(d ->> 'storeCode', '') !~ '^[A-Z0-9_-]{2,12}$' then return false; end if;
  if not public.dge_str(d -> 'customerName', 80) or length(d ->> 'customerName') < 2 then return false; end if;
  if jsonb_typeof(d -> 'mobile') is distinct from 'string'
     or (d ->> 'mobile') !~ '^([6-9][0-9]{9}|[+][1-9][0-9]{7,14})$' then return false; end if;
  if coalesce(d ->> 'customerType', '') not in ('Individual', 'Corporate', 'Bulk') then return false; end if;
  if coalesce(d ->> 'status', '') not in ('New', 'Follow-up', 'Converted', 'Lost') then return false; end if;
  if not public.dge_num(d -> 'estValue', 0, 100000000) then return false; end if;
  if not public.dge_num(d -> 'totalQty', 1, 1000000) then return false; end if;
  if jsonb_typeof(d -> 'isHot') is distinct from 'boolean' then return false; end if;
  if not public.dge_str(d -> 'gstin', 15) or not public.dge_str(d -> 'remarks', 300)
     or not public.dge_str(d -> 'company', 100) then return false; end if;
  if jsonb_typeof(d -> 'lines') is distinct from 'array' then return false; end if;
  if jsonb_array_length(d -> 'lines') not between 1 and 25 then return false; end if;
  if jsonb_typeof(d -> 'acts') is distinct from 'array' then return false; end if;
  if jsonb_array_length(d -> 'acts') > 300 then return false; end if;
  if not public.dge_num(d -> 'saleValue', 0, 100000000) then return false; end if;
  return true;
end $$;

-- The write rules (same as v5 firestore.rules)
create or replace function public.dge_allow_write(c jsonb, p_col text, p_id text, p_exists boolean, o jsonb, n jsonb)
returns boolean
language plpgsql stable security definer set search_path = public as $$
declare
  is_auth  boolean := coalesce((c ->> 'auth')::boolean, false);
  is_bound boolean := coalesce((c ->> 'bound')::boolean, false);
  is_admin boolean := coalesce((c ->> 'admin')::boolean, false);
  ch       text[];
begin
  if p_col = 'settings' then
    if not p_exists then
      -- first login on an empty database becomes Admin
      return is_auth and p_id = 'app' and n -> 'adminUids' = jsonb_build_array(c ->> 'uid');
    end if;
    return is_admin;

  elsif p_col = 'masters' then
    return is_admin and p_id in ('stores', 'products', 'escalation');

  elsif p_col = 'users' then
    if not p_exists then return is_admin; end if;
    if is_admin then return true; end if;
    ch := public.dge_changed(o, n);
    -- first login with default PIN (or after a reset): link this account to the code
    if is_auth and c ->> 'code' = p_id and coalesce(o ->> 'uid', '') = ''
       and c ->> 'k' = coalesce(o ->> 'k', '0') and n ->> 'uid' = c ->> 'uid'
       and ch <@ array['uid', 'claimedAt'] then return true; end if;
    -- owner changed own PIN
    if is_bound and c ->> 'code' = p_id and ch <@ array['pinSet', 'pinAt'] then return true; end if;
    -- Admin resets a PIN
    if is_bound and c ->> 'role' = 'ADMIN' and coalesce(n ->> 'uid', 'x') = ''
       and ch <@ array['uid', 'k', 'pinSet', 'resetBy', 'resetAt'] then return true; end if;
    return false;

  elsif p_col = 'pinResets' then
    return n ->> 'code' = p_id and length(p_id) <= 30
       and public.dge_keys(n) <@ array['code', 'role', 'name', 'amCode', 'zfm', 'at']
       and exists (select 1 from public.dge_docs where col = 'users' and id = p_id);

  elsif p_col = 'enquiries' then
    if not public.dge_valid_enq(n) then return false; end if;
    if not p_exists then
      return public.dge_can_see(c, n)
         and n ->> 'id' = p_id
         and p_id ~ ('^DW-' || (n ->> 'storeCode') || '-[0-9]{4}-[A-Z0-9]{2,6}$')
         and n ->> 'status' = 'New'
         and n -> 'followupCount' = '0'::jsonb;
    end if;
    ch := public.dge_changed(o, n);
    if not (public.dge_can_see(c, o)
       and ch <@ array[
             'status', 'nextFollowUp', 'lastContactAt', 'lastOutcome', 'followupCount', 'expectedPurchaseDate', 'priority',
             'acts', 'updatedAt', 'updatedBy', 'saleValue', 'saleQty', 'billNo', 'saleDate', 'lostReason', 'lostDate',
             'escalationStatus', 'lastEscalationAt', 'lastEscalationTo', 'escGroup',
             -- v8 edit (needs a reason, see below)
             'customerName', 'mobile', 'customerType', 'company', 'gstRequired', 'gstin', 'city', 'consent', 'consentAt',
             'lines', 'cats', 'totalQty', 'estValue', 'isHot', 'productSummary', 'intendedUse', 'remarks']) then
      return false;
    end if;
    -- v8: customer / product changes only on an open enquiry, and only together with an
    -- "EDITED" journey entry that carries the reason (at least 5 letters)
    if ch && array['customerName', 'mobile', 'customerType', 'company', 'gstRequired', 'gstin', 'city', 'consent', 'consentAt',
                   'lines', 'cats', 'totalQty', 'estValue', 'isHot', 'productSummary', 'intendedUse', 'remarks'] then
      if coalesce(o ->> 'status', '') not in ('New', 'Follow-up') or 'status' = any(ch) then return false; end if;
      if jsonb_array_length(n -> 'acts') <> jsonb_array_length(coalesce(o -> 'acts', '[]'::jsonb)) + 1 then return false; end if;
      if (n -> 'acts' -> -1 ->> 'type') is distinct from 'EDITED'
         or length(trim(coalesce(n -> 'acts' -> -1 ->> 'note', ''))) < 5 then return false; end if;
    end if;
    return true;

  elsif p_col = 'stats' then
    return is_bound
       and public.dge_keys(n) <@ array['date', 'zone', 's', 'cat', 'typ', 'lost', 'plost']
       and jsonb_typeof(n -> 'date') = 'string' and jsonb_typeof(n -> 'zone') = 'string';
  end if;
  return false;
end $$;

-- ---------- 3. Data API used by the app ----------
-- An ended session returns {"__expired": "<reason>"} instead of data,
-- so the app can log the user out with the reason.

-- read one document
create or replace function public.dge_get(p_token text, p_col text, p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c jsonb := public.dge_ctx(p_token);
  d jsonb;
  ok boolean;
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  select data into d from public.dge_docs where col = p_col and id = p_id;
  if d is null then return null; end if;
  ok := case p_col
          when 'settings'  then true
          when 'masters'   then true
          when 'users'     then true              -- login screen needs role + key
          when 'pinResets' then coalesce((c ->> 'admin')::boolean, false)
          when 'enquiries' then public.dge_can_see(c, d)
          when 'stats'     then coalesce((c ->> 'bound')::boolean, false)
          else false end;
  if not ok then raise exception 'permission-denied: Missing or insufficient permissions.'; end if;
  return d || jsonb_build_object('_id', p_id);
end $$;

-- query a collection: where = [[field, op, value], ...], order = [field, 'asc'|'desc']
-- p_mode 'rows' returns the documents, 'agg' returns {count, sum}
create or replace function public.dge_query(
  p_token text, p_col text, p_where jsonb default '[]'::jsonb, p_order jsonb default null,
  p_limit int default null, p_mode text default 'rows', p_sum text default null)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c      jsonb := public.dge_ctx(p_token);
  w      jsonb;
  f      text;
  op     text;
  v      jsonb;
  cond   text;
  ord    text := 'null::jsonb';
  dir    text := 'asc';
  lim    int  := least(greatest(coalesce(p_limit, 5000), 1), 5000);
  inlist text;
  res    jsonb;
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  cond := format('col = %L', p_col);

  if p_col = 'enquiries' then
    if coalesce((c ->> 'mgmt')::boolean, false) then
      null;
    elsif coalesce((c ->> 'bound')::boolean, false) and c ->> 'role' = 'STORE' then
      cond := cond || format(' and data->>''storeCode'' = %L', c ->> 'code');
    elsif coalesce((c ->> 'bound')::boolean, false) and c ->> 'role' = 'AM' then
      cond := cond || format(' and data->>''amCode'' = %L', c ->> 'code');
    else
      raise exception 'permission-denied: Missing or insufficient permissions.';
    end if;
  elsif p_col = 'stats' then
    if not coalesce((c ->> 'bound')::boolean, false) then
      raise exception 'permission-denied: Missing or insufficient permissions.';
    end if;
  elsif p_col in ('pinResets', 'users') then
    if not coalesce((c ->> 'admin')::boolean, false) then
      raise exception 'permission-denied: Missing or insufficient permissions.';
    end if;
  elsif p_col not in ('settings', 'masters') then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;

  if p_where is not null and jsonb_typeof(p_where) = 'array' then
    if jsonb_array_length(p_where) > 10 then raise exception 'invalid-argument: too many filters'; end if;
    for w in select * from jsonb_array_elements(p_where) loop
      f := w ->> 0; op := w ->> 1; v := w -> 2;
      if f is null or f !~ '^[A-Za-z_][A-Za-z0-9_]{0,40}$' then raise exception 'invalid-argument: bad field'; end if;
      if op = '==' then
        cond := cond || format(' and data->%L = %L::jsonb', f, coalesce(v, 'null'::jsonb)::text);
      elsif op = 'in' then
        if jsonb_typeof(v) is distinct from 'array' or jsonb_array_length(v) > 30 then
          raise exception 'invalid-argument: bad in-list';
        end if;
        select string_agg(format('%L::jsonb', e::text), ',') into inlist from jsonb_array_elements(v) e;
        cond := cond || case when inlist is null then ' and false' else format(' and data->%L in (%s)', f, inlist) end;
      elsif op in ('<', '<=', '>', '>=') then
        if v is null or jsonb_typeof(v) not in ('string', 'number', 'boolean') then
          raise exception 'invalid-argument: bad range value';
        end if;
        cond := cond || format(' and jsonb_typeof(data->%L) = %L and data->%L %s %L::jsonb',
                               f, jsonb_typeof(v), f, op, v::text);
      else
        raise exception 'invalid-argument: bad operator';
      end if;
    end loop;
  end if;

  if p_mode = 'agg' then
    if p_sum is not null and p_sum !~ '^[A-Za-z_][A-Za-z0-9_]{0,40}$' then raise exception 'invalid-argument: bad field'; end if;
    execute format(
      'select jsonb_build_object(''count'', count(*), ''sum'', %s) from public.dge_docs where %s',
      case when p_sum is null then '0'
           else format('coalesce(sum(case when jsonb_typeof(data->%L) = ''number'' then (data->>%L)::numeric end), 0)', p_sum, p_sum) end,
      cond) into res;
    return res;
  end if;

  if p_order is not null and jsonb_typeof(p_order) = 'array' and jsonb_array_length(p_order) > 0 then
    f := p_order ->> 0;
    if f is null or f !~ '^[A-Za-z_][A-Za-z0-9_]{0,40}$' then raise exception 'invalid-argument: bad order field'; end if;
    dir := lower(coalesce(p_order ->> 1, 'asc'));
    if dir not in ('asc', 'desc') then raise exception 'invalid-argument: bad order'; end if;
    cond := cond || format(' and data ? %L', f);
    ord  := format('data->%L', f);
  end if;

  execute format(
    'select coalesce(jsonb_agg(t.d order by t.o %s), ''[]''::jsonb) from (
       select data || jsonb_build_object(''_id'', id) as d, %s as o
         from public.dge_docs where %s order by %s %s limit %s) t',
    dir, ord, cond, ord, dir, lim) into res;
  return res;
end $$;

-- write a batch of documents (all or nothing)
-- ops = [{t:'set'|'update'|'del', col, id, data, merge}]
create or replace function public.dge_write(p_token text, p_ops jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c       jsonb := public.dge_ctx(p_token);
  op      jsonb;
  v_t     text;
  v_col   text;
  v_id    text;
  v_data  jsonb;
  v_merge boolean;
  o       jsonb;
  n       jsonb;
  v_exist boolean;
  now_ms  bigint := floor(extract(epoch from clock_timestamp()) * 1000);
  ok      boolean;
  v_saved boolean := false;
  v_ch    text[];
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if p_ops is null or jsonb_typeof(p_ops) <> 'array' or jsonb_array_length(p_ops) = 0 or jsonb_array_length(p_ops) > 500 then
    raise exception 'invalid-argument: bad batch';
  end if;
  if length(p_ops::text) > 2000000 then raise exception 'invalid-argument: batch too large'; end if;

  for op in select * from jsonb_array_elements(p_ops) loop
    v_t     := op ->> 't';
    v_col   := op ->> 'col';
    v_id    := op ->> 'id';
    v_data  := coalesce(op -> 'data', '{}'::jsonb);
    v_merge := coalesce((op ->> 'merge')::boolean, false);

    if v_col is null or v_col not in ('settings', 'masters', 'users', 'pinResets', 'enquiries', 'stats') then
      raise exception 'permission-denied: Missing or insufficient permissions.';
    end if;
    if v_id is null or v_id !~ '^[A-Za-z0-9_.-]{1,120}$' then raise exception 'invalid-argument: bad document id'; end if;
    if v_t is null or v_t not in ('set', 'update', 'del') then raise exception 'invalid-argument: bad operation'; end if;
    if v_t <> 'del' and jsonb_typeof(v_data) <> 'object' then raise exception 'invalid-argument: bad data'; end if;

    o := null;
    select data into o from public.dge_docs where col = v_col and id = v_id for update;
    v_exist := o is not null;

    if v_t = 'del' then
      if not v_exist then continue; end if;
      -- enquiries are deleted only through dge_delete_enquiry (Admin + reason, logged)
      if not (coalesce((c ->> 'admin')::boolean, false) and v_col in ('stats', 'pinResets', 'users')) then
        raise exception 'permission-denied: Missing or insufficient permissions.';
      end if;
      delete from public.dge_docs where col = v_col and id = v_id;
      continue;
    end if;

    if v_t = 'update' then
      if not v_exist then raise exception 'not-found: No document to update: %/%', v_col, v_id; end if;
      n := public.dge_apply(o, v_data, false, now_ms);
    elsif v_merge and v_exist then
      n := public.dge_apply(o, v_data, true, now_ms);
    else
      n := public.dge_apply('{}'::jsonb, v_data, true, now_ms);
    end if;

    if v_col = 'enquiries' then
      n := jsonb_set(n, '{updatedAt}', to_jsonb(now_ms));   -- server time, like serverTimestamp()
    end if;

    ok := public.dge_allow_write(c, v_col, v_id, v_exist, o, n);
    if not coalesce(ok, false) then
      raise exception 'permission-denied: Missing or insufficient permissions.';
    end if;

    insert into public.dge_docs (col, id, data, updated_at)
    values (v_col, v_id, n, clock_timestamp())
    on conflict (col, id) do update set data = excluded.data, updated_at = excluded.updated_at;

    -- log Admin PIN resets (new key) and reset requests
    if v_col = 'users' and v_exist and coalesce(o ->> 'k', '0') is distinct from coalesce(n ->> 'k', '0') then
      delete from public.dge_recovery where code = v_id;     -- the next person registers their own mobile
      perform public.dge_log(v_id, 'PIN_RESET_ADMIN', true, 'Reset by ' || coalesce(nullif(c ->> 'code', ''), 'Admin'), null);
    elsif v_col = 'pinResets' then
      perform public.dge_log(v_id, 'PIN_REQUEST', true, 'Asked Central Ops to reset the PIN', null);
    end if;

    if v_col = 'enquiries' then
      v_saved := true;
      -- v8: an edit (new "EDITED" journey entry) goes into the Edit & delete log
      if v_exist and jsonb_array_length(coalesce(n -> 'acts', '[]'::jsonb)) > jsonb_array_length(coalesce(o -> 'acts', '[]'::jsonb))
         and (n -> 'acts' -> -1 ->> 'type') = 'EDITED' then
        select coalesce(array_agg(x), '{}'::text[]) into v_ch
          from unnest(public.dge_changed(o, n)) x where x not in ('acts', 'updatedAt', 'updatedBy', 'cats', 'consentAt');
        insert into public.dge_audit (code, action, enq_id, store_code, reason, detail)
        values (coalesce(nullif(c ->> 'code', ''), '?'), 'EDIT', v_id, n ->> 'storeCode', left(n -> 'acts' -> -1 ->> 'note', 300),
                jsonb_build_object('fields', to_jsonb(v_ch),
                                   'before', public.dge_audit_view(o, v_ch), 'after', public.dge_audit_view(n, v_ch)));
      end if;
    end if;
  end loop;
  -- v8: any enquiry write counts as "saved" for the store no-save time-out
  if v_saved and c ->> 'th' is not null then
    update public.dge_sessions set last_save = now() where token_hash = c ->> 'th';
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- 4. Code + PIN login ----------
create or replace function public.dge_has_recovery(p_code text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.dge_recovery where code = upper(p_code));
$$;

create or replace function public.dge_new_session(p_email text, p_uid uuid, p_meta jsonb default null) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare
  tok    text := encode(extensions.gen_random_bytes(32), 'hex');
  st     jsonb;
  v_max  int;
  v_code text := upper(split_part(split_part(p_email, '@', 1), '.', 1));
  v_role text;
begin
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  v_max := public.dge_set_int(st, 'sessionMins', 720, 30, 43200);
  select data ->> 'role' into v_role from public.dge_docs where col = 'users' and id = v_code;
  if v_role is null and st is null then v_role := 'ADMIN'; end if;     -- first-time setup
  -- housekeeping on a few logins only (keeps the morning login rush light)
  if random() < 0.05 then
    delete from public.dge_sessions where expires_at < now() - interval '1 hour' or last_seen < now() - interval '2 days';
  end if;
  insert into public.dge_sessions (token_hash, email, uid, expires_at, last_seen, last_save, code, role, meta)
  values (encode(extensions.digest(tok, 'sha256'), 'hex'), p_email, p_uid, now() + make_interval(mins => v_max), now(), now(),
          v_code, v_role, public.dge_clean_meta(p_meta));
  return tok;
end $$;

create or replace function public.dge_sign_in(p_email text, p_pin text, p_meta jsonb default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_email  text := lower(trim(coalesce(p_email, '')));
  v_code   text := upper(split_part(split_part(lower(trim(coalesce(p_email, ''))), '@', 1), '.', 1));
  v_hash   text;
  v_uid    uuid;
  v_failed int;
  v_locked timestamptz;
begin
  if v_email !~ '^[a-z0-9_-]{2,30}\.[a-z0-9]{1,12}@vmm-diwali\.app$' or coalesce(p_pin, '') !~ '^[0-9]{6}$' then
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-credential');
  end if;
  select pin_hash, uid, failed, locked_until into v_hash, v_uid, v_failed, v_locked
    from public.dge_logins where email = v_email for update;
  if v_hash is null then
    if p_pin <> '456987' then perform public.dge_log(v_code, 'LOGIN', false, 'Wrong PIN', p_meta); end if;
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-credential');
  end if;
  if v_locked is not null and v_locked > now() then
    perform public.dge_log(v_code, 'LOGIN', false, 'Locked – too many wrong PINs', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/too-many-requests');
  end if;
  if v_hash <> extensions.crypt(p_pin, v_hash) then
    update public.dge_logins
       set failed = failed + 1,
           locked_until = case when failed + 1 >= 5 then now() + interval '15 minutes' end
     where email = v_email;
    perform public.dge_log(v_code, 'LOGIN', false,
      case when v_failed + 1 >= 5 then 'Wrong PIN – locked for 15 min' else 'Wrong PIN (' || (v_failed + 1) || ' of 5)' end, p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-credential');
  end if;
  update public.dge_logins set failed = 0, locked_until = null where email = v_email;
  perform public.dge_log(v_code, 'LOGIN', true, 'Logged in', p_meta);
  return jsonb_build_object('ok', true, 'email', v_email, 'uid', v_uid,
    'token', public.dge_new_session(v_email, v_uid, p_meta), 'hasRecovery', public.dge_has_recovery(v_code));
end $$;

-- first login with the default PIN creates the account (only when the code is free to claim)
create or replace function public.dge_create_login(p_email text, p_pin text, p_meta jsonb default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_email text := lower(trim(coalesce(p_email, '')));
  v_local text;
  v_code  text;
  v_k     text;
  u       jsonb;
  st      jsonb;
  v_uid   uuid;
begin
  if v_email !~ '^[a-z0-9_-]{2,30}\.[a-z0-9]{1,12}@vmm-diwali\.app$' or coalesce(p_pin, '') <> '456987' then
    return jsonb_build_object('ok', false, 'code', 'auth/operation-not-allowed');
  end if;
  v_local := split_part(v_email, '@', 1);
  v_code  := upper(split_part(v_local, '.', 1));
  v_k     := split_part(v_local, '.', 2);
  if exists (select 1 from public.dge_logins where email = v_email) then
    perform public.dge_log(v_code, 'LOGIN', false, 'Default PIN used but own PIN already set', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/email-already-in-use');
  end if;
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  select data into u  from public.dge_docs where col = 'users'    and id = v_code;
  if not (st is null or (u is not null and coalesce(u ->> 'uid', '') = '' and coalesce(u ->> 'k', '0') = v_k)) then
    return jsonb_build_object('ok', false, 'code', 'auth/operation-not-allowed');
  end if;
  insert into public.dge_logins (email, pin_hash)
  values (v_email, extensions.crypt(p_pin, extensions.gen_salt('bf', 6)))
  returning uid into v_uid;
  perform public.dge_log(v_code, 'FIRST_LOGIN', true, 'Logged in with default PIN', p_meta);
  return jsonb_build_object('ok', true, 'email', v_email, 'uid', v_uid,
    'token', public.dge_new_session(v_email, v_uid, p_meta), 'hasRecovery', public.dge_has_recovery(v_code));
end $$;

create or replace function public.dge_change_pin(p_token text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  c    jsonb := public.dge_ctx(p_token);
  v_th text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
begin
  if not coalesce((c ->> 'auth')::boolean, false) then
    return jsonb_build_object('ok', false, 'code', 'unauthenticated', 'message', coalesce(nullif(c ->> 'why', ''), 'Please log in again.'));
  end if;
  if public.dge_weak_pin(p_pin) then
    return jsonb_build_object('ok', false, 'code', 'auth/weak-password', 'message', 'Too easy – choose a different 6-digit PIN');
  end if;
  update public.dge_logins
     set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf', 6)), pin_changed_at = now(), failed = 0, locked_until = null
   where email = c ->> 'email';
  delete from public.dge_sessions where email = c ->> 'email' and token_hash <> v_th;   -- sign out other phones
  perform public.dge_log(c ->> 'code', 'PIN_CHANGED', true, 'Set own PIN', null);
  return jsonb_build_object('ok', true);
end $$;

-- register / update the mobile used for self-service Forgot PIN
create or replace function public.dge_set_recovery(p_token text, p_mobile text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  c  jsonb := public.dge_ctx(p_token);
  u  jsonb;
  st jsonb;
  v_code text;
begin
  if not coalesce((c ->> 'auth')::boolean, false) then
    return jsonb_build_object('ok', false, 'code', 'unauthenticated', 'message', coalesce(nullif(c ->> 'why', ''), 'Please log in again.'));
  end if;
  if coalesce(p_mobile, '') !~ '^[6-9][0-9]{9}$' then
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-mobile', 'message', 'Enter a valid 10-digit mobile number');
  end if;
  v_code := c ->> 'code';
  select data into u  from public.dge_docs where col = 'users'    and id = v_code;
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  if not (coalesce((c ->> 'bound')::boolean, false) or (u is null and st is null)) then
    return jsonb_build_object('ok', false, 'code', 'permission-denied', 'message', 'Not allowed for this login');
  end if;
  insert into public.dge_recovery (code, mobile_hash, last4)
  values (v_code, extensions.crypt(p_mobile, extensions.gen_salt('bf', 6)), right(p_mobile, 4))
  on conflict (code) do update set mobile_hash = excluded.mobile_hash, last4 = excluded.last4,
                                   set_at = now(), failed = 0, locked_until = null;
  perform public.dge_log(v_code, 'MOBILE_REGISTERED', true, 'Mobile ending ' || right(p_mobile, 4), null);
  return jsonb_build_object('ok', true);
end $$;

-- Forgot PIN: code + registered mobile + new PIN -> new PIN set and logged in. No Admin needed.
create or replace function public.dge_self_reset(p_code text, p_mobile text, p_pin text, p_meta jsonb default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_code   text := upper(trim(coalesce(p_code, '')));
  u        jsonb;
  v_hash   text;
  v_failed int;
  v_locked timestamptz;
  v_k      text;
  v_email  text;
  v_uid    uuid;
  v_now    text := public.dge_now_ist();
begin
  if v_code !~ '^[A-Z0-9_-]{2,30}$' then
    return jsonb_build_object('ok', false, 'code', 'auth/not-in-master');
  end if;
  select data into u from public.dge_docs where col = 'users' and id = v_code;
  if u is null then
    perform public.dge_log(v_code, 'PIN_RESET_SELF', false, 'Code not in master', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/not-in-master');
  end if;
  if public.dge_weak_pin(p_pin) then
    return jsonb_build_object('ok', false, 'code', 'auth/weak-password', 'message', 'Too easy – choose a different 6-digit PIN');
  end if;
  if coalesce(p_mobile, '') !~ '^[6-9][0-9]{9}$' then
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-mobile', 'message', 'Enter your registered 10-digit mobile number');
  end if;
  select mobile_hash, failed, locked_until into v_hash, v_failed, v_locked
    from public.dge_recovery where code = v_code for update;
  if v_hash is null then
    perform public.dge_log(v_code, 'PIN_RESET_SELF', false, 'No registered mobile', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/no-recovery');
  end if;
  if v_locked is not null and v_locked > now() then
    perform public.dge_log(v_code, 'PIN_RESET_SELF', false, 'Locked – too many wrong mobiles', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/too-many-requests');
  end if;
  if v_hash <> extensions.crypt(p_mobile, v_hash) then
    update public.dge_recovery
       set failed = failed + 1,
           locked_until = case when failed + 1 >= 5 then now() + interval '30 minutes' end
     where code = v_code;
    perform public.dge_log(v_code, 'PIN_RESET_SELF', false, 'Wrong mobile (' || (v_failed + 1) || ' of 5)', p_meta);
    return jsonb_build_object('ok', false, 'code', 'auth/wrong-mobile');
  end if;
  update public.dge_recovery set failed = 0, locked_until = null where code = v_code;

  -- new login key: every old login and phone of this code stops working
  v_k     := substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 8);
  v_email := lower(v_code) || '.' || v_k || '@vmm-diwali.app';
  delete from public.dge_logins where split_part(split_part(email, '@', 1), '.', 1) = lower(v_code);
  insert into public.dge_logins (email, pin_hash, pin_changed_at)
  values (v_email, extensions.crypt(p_pin, extensions.gen_salt('bf', 6)), now())
  returning uid into v_uid;
  update public.dge_docs
     set data = data || jsonb_build_object('uid', v_uid::text, 'k', v_k, 'pinSet', true, 'pinAt', v_now,
                                           'resetBy', 'SELF', 'resetAt', v_now),
         updated_at = now()
   where col = 'users' and id = v_code;
  delete from public.dge_docs where col = 'pinResets' and id = v_code;
  perform public.dge_log(v_code, 'PIN_RESET_SELF', true, 'New PIN set with registered mobile', p_meta);
  return jsonb_build_object('ok', true, 'email', v_email, 'uid', v_uid,
    'token', public.dge_new_session(v_email, v_uid, p_meta), 'hasRecovery', true);
end $$;

create or replace function public.dge_whoami(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare c jsonb := public.dge_ctx(p_token);
begin
  if not coalesce((c ->> 'auth')::boolean, false) then return null; end if;
  return jsonb_build_object('email', c ->> 'email', 'uid', c ->> 'uid', 'hasRecovery', public.dge_has_recovery(c ->> 'code'));
end $$;

create or replace function public.dge_sign_out(p_token text, p_reason text default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_th    text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_email text;
begin
  delete from public.dge_sessions where token_hash = v_th returning email into v_email;
  if v_email is not null then
    perform public.dge_log(upper(split_part(split_part(v_email, '@', 1), '.', 1)),
      case when coalesce(p_reason, '') = '' then 'LOGOUT' else 'SESSION_END' end, true,
      coalesce(nullif(left(p_reason, 120), ''), 'Logged out'), null);
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- Admin: login / PIN log (newest first), with registered-mobile status
create or replace function public.dge_auth_log_list(p_token text, p_code text default null, p_event text default null, p_limit int default 300)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c   jsonb := public.dge_ctx(p_token);
  res jsonb;
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if not coalesce((c ->> 'admin')::boolean, false) then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object(
           'at', to_char(l.at at time zone 'Asia/Kolkata', 'YYYY-MM-DD HH24:MI:SS'),
           'code', l.code, 'event', l.event, 'ok', l.ok, 'detail', l.detail,
           'desig', l.meta ->> 'desig', 'km', l.meta -> 'km', 'test', l.meta -> 'test', 'ua', l.meta ->> 'ua')
         order by l.at desc), '[]'::jsonb)
    into res
    from (select * from public.dge_auth_log
           where (coalesce(p_code, '') = '' or code = upper(trim(p_code)))
             and (coalesce(p_event, '') = '' or event = p_event)
           order by at desc
           limit least(greatest(coalesce(p_limit, 300), 1), 2000)) l;
  return jsonb_build_object('rows', res,
    'registered', (select count(*) from public.dge_recovery),
    'mobile', case when coalesce(p_code, '') = '' then null
                   else (select last4 from public.dge_recovery where code = upper(trim(p_code))) end);
end $$;

-- ---------- 4b. v8: Admin delete, Sessions tab, Edit & delete log ----------

-- add / subtract counters in one daily zone summary (same layout the app writes)
create or replace function public.dge_stat_add(p_date text, p_zone text, p_upd jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_id   text;
  o      jsonb;
  now_ms bigint := floor(extract(epoch from clock_timestamp()) * 1000);
begin
  if coalesce(p_date, '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' or coalesce(p_zone, '') = '' then return; end if;
  v_id := p_date || '_' || p_zone;
  select data into o from public.dge_docs where col = 'stats' and id = v_id for update;
  insert into public.dge_docs (col, id, data, updated_at)
  values ('stats', v_id, public.dge_apply(coalesce(o, '{}'::jsonb), p_upd || jsonb_build_object('date', p_date, 'zone', p_zone), true, now_ms), clock_timestamp())
  on conflict (col, id) do update set data = excluded.data, updated_at = excluded.updated_at;
end $$;

-- Admin deletes an enquiry with a reason. Dashboards are corrected, the full record is kept
-- in the Edit & delete log, and phones drop it on their next refresh (tombstone).
create or replace function public.dge_delete_enquiry(p_token text, p_id text, p_reason text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c        jsonb := public.dge_ctx(p_token);
  d        jsonb;
  v_reason text := left(trim(coalesce(p_reason, '')), 300);
  s        text;
  z        text;
  t        jsonb;
  v_cat    jsonb;
  v_plost  jsonb;
  v_val    numeric;
  m1       jsonb := '{"__inc": -1}'::jsonb;
  now_ms   bigint := floor(extract(epoch from clock_timestamp()) * 1000);
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if not coalesce((c ->> 'admin')::boolean, false) then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;
  if length(v_reason) < 5 then raise exception 'invalid-argument: Give a reason (at least 5 letters).'; end if;
  select data into d from public.dge_docs where col = 'enquiries' and id = p_id for update;
  if d is null then raise exception 'not-found: Enquiry not found.'; end if;
  if coalesce((d ->> 'deleted')::boolean, false) then raise exception 'invalid-argument: This enquiry is already deleted.'; end if;

  s := d ->> 'storeCode';
  z := coalesce(nullif(d ->> 'zone', ''), 'Z_' || coalesce(nullif(regexp_replace(coalesce(d ->> 'zfm', 'NA'), '[^A-Za-z0-9]', '', 'g'), ''), 'NA'));
  v_val := case when jsonb_typeof(d -> 'estValue') = 'number' then (d ->> 'estValue')::numeric else 0 end;

  -- 1. take it out of the capture day
  select coalesce(jsonb_object_agg(k, jsonb_build_object('__inc', -((v #>> '{}')::numeric))), '{}'::jsonb) into v_cat
    from jsonb_each(case when jsonb_typeof(d -> 'cats') = 'object' then d -> 'cats' else '{}'::jsonb end) as x(k, v)
   where jsonb_typeof(v) = 'number';
  perform public.dge_stat_add(d ->> 'createdDate', z, jsonb_build_object(
    's', jsonb_build_object(s, jsonb_strip_nulls(jsonb_build_object(
           'e', m1, 'v', jsonb_build_object('__inc', -v_val),
           'h', case when d ->> 'isHot' = 'true' then m1 end,
           'b', case when coalesce(d ->> 'customerType', 'Individual') <> 'Individual' then m1 end,
           'g', case when d ->> 'gstRequired' = 'Yes' then m1 end))),
    'cat', v_cat,
    'typ', jsonb_build_object(coalesce(d ->> 'customerType', 'Individual'), jsonb_build_object('n', m1, 'v', jsonb_build_object('__inc', -v_val)))));

  -- 2. first follow-up / outcome day
  select a into t from jsonb_array_elements(coalesce(d -> 'acts', '[]'::jsonb)) a
   where a ->> 'type' in ('FOLLOWUP', 'CONVERTED', 'LOST') order by a ->> 'at' limit 1;
  if t is not null then
    perform public.dge_stat_add(case when t ->> 'type' = 'CONVERTED' and coalesce(d ->> 'saleDate', '') <> '' then d ->> 'saleDate' else left(t ->> 'at', 10) end,
      z, jsonb_build_object('s', jsonb_build_object(s, jsonb_build_object('f', m1))));
  end if;

  -- 3. outcome
  if d ->> 'status' = 'Converted' then
    perform public.dge_stat_add(d ->> 'saleDate', z, jsonb_build_object(
      's', jsonb_build_object(s, jsonb_build_object('c', m1, 'cv', jsonb_build_object('__inc', -round(case when jsonb_typeof(d -> 'saleValue') = 'number' then (d ->> 'saleValue')::numeric else 0 end)))),
      'typ', jsonb_build_object(coalesce(d ->> 'customerType', 'Individual'), jsonb_build_object('c', m1))));
  elsif d ->> 'status' = 'Lost' then
    if d ->> 'lostReason' = 'Product unavailable' then
      select coalesce(jsonb_object_agg(left(regexp_replace(coalesce(l ->> 'name', 'Other'), '[^A-Za-z0-9]', '_', 'g'), 60),
                                       jsonb_build_object('__inc', -coalesce((l ->> 'qty')::numeric, 0))), '{}'::jsonb)
        into v_plost from jsonb_array_elements(coalesce(d -> 'lines', '[]'::jsonb)) l;
    end if;
    perform public.dge_stat_add(d ->> 'lostDate', z, jsonb_build_object(
      's', jsonb_build_object(s, jsonb_build_object('l', m1)),
      'lost', jsonb_build_object(regexp_replace(coalesce(d ->> 'lostReason', 'Other'), '[^A-Za-z0-9]', '_', 'g'), m1),
      'plost', coalesce(v_plost, '{}'::jsonb)));
  end if;

  -- 4. keep the full record in the log, leave a tombstone without customer data
  insert into public.dge_audit (code, action, enq_id, store_code, reason, detail)
  values (coalesce(nullif(c ->> 'code', ''), '?'), 'DELETE', p_id, s, v_reason, jsonb_build_object(
    'summary', jsonb_build_object('customerName', d ->> 'customerName', 'mobile', left(d ->> 'mobile', 2) || '•••••' || right(d ->> 'mobile', 3),
                                  'customerType', d ->> 'customerType', 'status', d ->> 'status', 'estValue', d -> 'estValue',
                                  'productSummary', d ->> 'productSummary', 'createdDate', d ->> 'createdDate', 'capturedBy', d ->> 'capturedBy'),
    'snapshot', d));
  update public.dge_docs
     set data = jsonb_build_object('id', p_id, 'storeCode', s, 'storeName', d -> 'storeName', 'amCode', d -> 'amCode', 'zfm', d -> 'zfm',
                                   'zone', z, 'createdDate', d -> 'createdDate', 'status', 'Deleted', 'deleted', true,
                                   'deletedAt', public.dge_now_ist(), 'deletedBy', c ->> 'code', 'deleteReason', v_reason, 'updatedAt', now_ms),
         updated_at = clock_timestamp()
   where col = 'enquiries' and id = p_id;
  if random() < 0.02 then delete from public.dge_audit where at < now() - interval '180 days'; end if;
  return jsonb_build_object('ok', true, 'deleted', p_id);
end $$;

-- Admin › Sessions: who is logged in now, and who logged in today
create or replace function public.dge_admin_sessions(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c        jsonb := public.dge_ctx(p_token);
  st       jsonb;
  v_idle   int;
  v_max    int;
  v_nosave int;
  v_now    jsonb;
  v_today  jsonb;
  v_day    timestamptz := (date_trunc('day', now() at time zone 'Asia/Kolkata')) at time zone 'Asia/Kolkata';
  v_fmt    text := 'YYYY-MM-DD HH24:MI';
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if not coalesce((c ->> 'admin')::boolean, false) then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  v_idle   := public.dge_set_int(st, 'idleMins', 15, 5, 1440);
  v_max    := public.dge_set_int(st, 'sessionMins', 720, 30, 43200);
  v_nosave := public.dge_set_int(st, 'noSaveMins', 10, 0, 720);
  delete from public.dge_sessions where expires_at < now() - interval '1 hour' or last_seen < now() - interval '2 days';

  select coalesce(jsonb_agg(jsonb_build_object(
           'sid', left(s.token_hash, 12), 'code', s.code, 'role', s.role,
           'desig', s.meta ->> 'desig', 'km', s.meta -> 'km', 'test', s.meta -> 'test', 'ua', s.meta ->> 'ua',
           'login', to_char(s.created_at at time zone 'Asia/Kolkata', v_fmt),
           'seen',  to_char(s.last_seen  at time zone 'Asia/Kolkata', v_fmt),
           'saved', to_char(s.last_save  at time zone 'Asia/Kolkata', v_fmt),
           'idleMin', floor(extract(epoch from now() - s.last_seen) / 60),
           'saveMin', floor(extract(epoch from now() - s.last_save) / 60),
           'me', s.token_hash = c ->> 'th')
         order by s.last_seen desc), '[]'::jsonb)
    into v_now
    from (select * from public.dge_sessions s
           where s.end_reason is null and s.expires_at > now()
             and s.created_at > now() - make_interval(mins => v_max)
             and s.last_seen  > now() - make_interval(mins => v_idle)
             and not (coalesce(s.role, '') = 'STORE' and v_nosave > 0 and s.last_save < now() - make_interval(mins => v_nosave))
           order by s.last_seen desc limit 3000) s;

  select coalesce(jsonb_agg(jsonb_build_object('code', x.code, 'first', to_char(x.f at time zone 'Asia/Kolkata', v_fmt),
           'last', to_char(x.l at time zone 'Asia/Kolkata', v_fmt), 'logins', x.n, 'desig', x.desig, 'km', x.km, 'test', x.test)
         order by x.l desc), '[]'::jsonb)
    into v_today
    from (select code, min(at) f, max(at) l, count(*) n,
                 (array_agg(meta ->> 'desig' order by at desc))[1] desig,
                 (array_agg(meta -> 'km' order by at desc))[1] km,
                 (array_agg(meta -> 'test' order by at desc))[1] test
            from public.dge_auth_log
           where at >= v_day and ok and event in ('LOGIN', 'FIRST_LOGIN', 'PIN_RESET_SELF')
           group by code order by max(at) desc limit 3000) x;

  return jsonb_build_object('now', v_now, 'today', v_today, 'idleMins', v_idle, 'noSaveMins', v_nosave, 'sessionMins', v_max,
                            'at', to_char(now() at time zone 'Asia/Kolkata', 'YYYY-MM-DD HH24:MI:SS'));
end $$;

-- Admin ends one session (p_sid) or every session of a code (p_code)
create or replace function public.dge_force_logout(p_token text, p_sid text, p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c   jsonb := public.dge_ctx(p_token);
  r   record;
  n   int := 0;
  why text;
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if not coalesce((c ->> 'admin')::boolean, false) then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;
  if coalesce(p_sid, '') = '' and coalesce(p_code, '') = '' then raise exception 'invalid-argument: Pick a session or a code.'; end if;
  why := 'Logged out by Admin (' || coalesce(nullif(c ->> 'code', ''), 'Admin') || ') – please log in again.';
  for r in update public.dge_sessions
              set end_reason = why, expires_at = now()
            where end_reason is null
              and token_hash is distinct from c ->> 'th'                 -- never your own session
              and ((coalesce(p_sid, '') <> '' and left(token_hash, 12) = p_sid)
                or (coalesce(p_sid, '') = '' and code = upper(trim(p_code))))
           returning code loop
    n := n + 1;
    perform public.dge_log(r.code, 'SESSION_END', true, 'Forced logout by Admin ' || coalesce(nullif(c ->> 'code', ''), ''), null);
  end loop;
  return jsonb_build_object('ok', true, 'ended', n);
end $$;

-- Admin › Edit & delete log (newest first; the deleted record itself is not sent to the phone)
create or replace function public.dge_audit_list(p_token text, p_store text default null, p_action text default null, p_limit int default 500)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c   jsonb := public.dge_ctx(p_token);
  res jsonb;
begin
  if (c ->> 'expired')::boolean then return jsonb_build_object('__expired', c ->> 'why'); end if;
  if not coalesce((c ->> 'admin')::boolean, false) then
    raise exception 'permission-denied: Missing or insufficient permissions.';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object(
           'at', to_char(a.at at time zone 'Asia/Kolkata', 'YYYY-MM-DD HH24:MI:SS'), 'code', a.code, 'action', a.action,
           'enq', a.enq_id, 'store', a.store_code, 'reason', a.reason, 'detail', coalesce(a.detail, '{}'::jsonb) - 'snapshot')
         order by a.at desc), '[]'::jsonb)
    into res
    from (select * from public.dge_audit
           where (coalesce(p_store, '') = '' or store_code = upper(trim(p_store)))
             and (coalesce(p_action, '') = '' or action = p_action)
           order by at desc
           limit least(greatest(coalesce(p_limit, 500), 1), 2000)) a;
  return jsonb_build_object('rows', res);
end $$;

-- ---------- 5. Who may call what ----------
-- Supabase gives anon/authenticated EXECUTE on new functions by default: take it away first.
revoke execute on function
  public.dge_str(jsonb, int), public.dge_num(jsonb, numeric, numeric), public.dge_set_int(jsonb, text, int, int, int),
  public.dge_changed(jsonb, jsonb), public.dge_keys(jsonb), public.dge_weak_pin(text), public.dge_clean_meta(jsonb),
  public.dge_log(text, text, boolean, text, jsonb), public.dge_now_ist(),
  public.dge_apply(jsonb, jsonb, boolean, bigint), public.dge_ctx(text),
  public.dge_can_see(jsonb, jsonb), public.dge_valid_enq(jsonb),
  public.dge_allow_write(jsonb, text, text, boolean, jsonb, jsonb), public.dge_has_recovery(text),
  public.dge_new_session(text, uuid, jsonb), public.dge_audit_view(jsonb, text[]), public.dge_stat_add(text, text, jsonb),
  public.dge_get(text, text, text), public.dge_query(text, text, jsonb, jsonb, int, text, text),
  public.dge_write(text, jsonb), public.dge_sign_in(text, text, jsonb), public.dge_create_login(text, text, jsonb),
  public.dge_change_pin(text, text), public.dge_set_recovery(text, text), public.dge_self_reset(text, text, text, jsonb),
  public.dge_whoami(text), public.dge_sign_out(text, text), public.dge_auth_log_list(text, text, text, int),
  public.dge_delete_enquiry(text, text, text), public.dge_admin_sessions(text), public.dge_force_logout(text, text, text),
  public.dge_audit_list(text, text, text, int)
from public, anon, authenticated;

-- only the app's entry points are callable from the browser
grant execute on function
  public.dge_get(text, text, text), public.dge_query(text, text, jsonb, jsonb, int, text, text),
  public.dge_write(text, jsonb), public.dge_sign_in(text, text, jsonb), public.dge_create_login(text, text, jsonb),
  public.dge_change_pin(text, text), public.dge_set_recovery(text, text), public.dge_self_reset(text, text, text, jsonb),
  public.dge_whoami(text), public.dge_sign_out(text, text), public.dge_auth_log_list(text, text, text, int),
  public.dge_delete_enquiry(text, text, text), public.dge_admin_sessions(text), public.dge_force_logout(text, text, text),
  public.dge_audit_list(text, text, text, int)
to anon, authenticated;

notify pgrst, 'reload schema';
