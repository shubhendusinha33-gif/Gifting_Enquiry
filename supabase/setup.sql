-- =====================================================================
-- VMM Diwali Gifting Enquiry – Supabase backend (v6)
-- Same app and screens as v5. Firestore is replaced by one Postgres
-- table of documents. Every read and write goes through the functions
-- below, which apply the same access rules as v5's firestore.rules.
-- Browsers can never touch the tables directly (RLS on, no policies).
--
-- Run this whole file once in Supabase › SQL Editor › New query › Run.
-- It is safe to run again (it replaces the functions, keeps the data).
-- =====================================================================

-- ---------- 0. Remove the test objects created during set-up ----------
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

alter table public.dge_docs     enable row level security;
alter table public.dge_logins   enable row level security;
alter table public.dge_sessions enable row level security;
revoke all on public.dge_docs, public.dge_logins, public.dge_sessions from public, anon, authenticated;

create index if not exists dge_enq_store_upd on public.dge_docs ((data->'storeCode'), (data->'updatedAt')) where col = 'enquiries';
create index if not exists dge_enq_am_upd    on public.dge_docs ((data->'amCode'), (data->'updatedAt'))    where col = 'enquiries';
create index if not exists dge_enq_mobile    on public.dge_docs ((data->'mobile'))                         where col = 'enquiries';
create index if not exists dge_enq_status    on public.dge_docs ((data->'status'))                         where col = 'enquiries';
create index if not exists dge_enq_zfm       on public.dge_docs ((data->'zfm'))                            where col = 'enquiries';
create index if not exists dge_stats_date    on public.dge_docs ((data->'date'))                           where col = 'stats';
create index if not exists dge_sessions_exp  on public.dge_sessions (expires_at);
create index if not exists dge_sessions_mail on public.dge_sessions (email);

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

-- keys whose value differs between two versions of a document
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
create or replace function public.dge_ctx(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare
  v_email text;
  v_uid   uuid;
  v_local text;
  v_code  text := '';
  v_k     text := '';
  u       jsonb;
  st      jsonb;
  v_bound boolean := false;
  v_role  text := '';
  v_admin boolean := false;
begin
  if p_token is not null and length(p_token) between 32 and 128 then
    select s.email, s.uid into v_email, v_uid
      from public.dge_sessions s
     where s.token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
       and s.expires_at > now();
  end if;
  if v_email is not null then
    v_local := split_part(v_email, '@', 1);
    v_code  := upper(split_part(v_local, '.', 1));
    v_k     := split_part(v_local, '.', 2);
    select data into u from public.dge_docs where col = 'users' and id = v_code;
    v_bound := u is not null and coalesce(u ->> 'uid', '') = v_uid::text;
    if v_bound then v_role := coalesce(u ->> 'role', ''); end if;
    select data into st from public.dge_docs where col = 'settings' and id = 'app';
    v_admin := st is not null and (
                 (jsonb_typeof(st -> 'adminUids') = 'array' and (st -> 'adminUids') ? v_uid::text)
                 or (v_bound and v_role = 'ADMIN'));
  end if;
  return jsonb_build_object(
    'email', v_email, 'uid', v_uid, 'code', v_code, 'k', v_k,
    'auth',  v_email is not null,
    'bound', v_bound, 'role', v_role, 'admin', v_admin,
    'mgmt',  v_bound and v_role in ('ZFM', 'HO', 'ADMIN'));
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
    return public.dge_can_see(c, o)
       and public.dge_changed(o, n) <@ array[
             'status', 'nextFollowUp', 'lastContactAt', 'lastOutcome', 'followupCount', 'expectedPurchaseDate', 'priority',
             'acts', 'updatedAt', 'updatedBy', 'saleValue', 'saleQty', 'billNo', 'saleDate', 'lostReason', 'lostDate',
             'escalationStatus', 'lastEscalationAt', 'lastEscalationTo', 'escGroup'];

  elsif p_col = 'stats' then
    return is_bound
       and public.dge_keys(n) <@ array['date', 'zone', 's', 'cat', 'typ', 'lost', 'plost']
       and jsonb_typeof(n -> 'date') = 'string' and jsonb_typeof(n -> 'zone') = 'string';
  end if;
  return false;
end $$;

-- ---------- 3. Data API used by the app ----------

-- read one document
create or replace function public.dge_get(p_token text, p_col text, p_id text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  c jsonb := public.dge_ctx(p_token);
  d jsonb;
  ok boolean;
begin
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
language plpgsql stable security definer set search_path = public as $$
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
begin
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
      if not (coalesce((c ->> 'admin')::boolean, false) and v_col in ('enquiries', 'stats', 'pinResets', 'users')) then
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
  end loop;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- 4. Code + PIN login ----------
create or replace function public.dge_new_session(p_email text, p_uid uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare tok text := encode(extensions.gen_random_bytes(32), 'hex');
begin
  delete from public.dge_sessions where expires_at < now();
  insert into public.dge_sessions (token_hash, email, uid, expires_at)
  values (encode(extensions.digest(tok, 'sha256'), 'hex'), p_email, p_uid, now() + interval '30 days');
  return tok;
end $$;

create or replace function public.dge_sign_in(p_email text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_email  text := lower(trim(coalesce(p_email, '')));
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
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-credential');
  end if;
  if v_locked is not null and v_locked > now() then
    return jsonb_build_object('ok', false, 'code', 'auth/too-many-requests');
  end if;
  if v_hash <> extensions.crypt(p_pin, v_hash) then
    update public.dge_logins
       set failed = failed + 1,
           locked_until = case when failed + 1 >= 5 then now() + interval '15 minutes' end
     where email = v_email;
    return jsonb_build_object('ok', false, 'code', 'auth/invalid-credential');
  end if;
  update public.dge_logins set failed = 0, locked_until = null where email = v_email;
  return jsonb_build_object('ok', true, 'email', v_email, 'uid', v_uid, 'token', public.dge_new_session(v_email, v_uid));
end $$;

-- first login with the default PIN creates the account (only when the code is free to claim)
create or replace function public.dge_create_login(p_email text, p_pin text) returns jsonb
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
  if exists (select 1 from public.dge_logins where email = v_email) then
    return jsonb_build_object('ok', false, 'code', 'auth/email-already-in-use');
  end if;
  v_local := split_part(v_email, '@', 1);
  v_code  := upper(split_part(v_local, '.', 1));
  v_k     := split_part(v_local, '.', 2);
  select data into st from public.dge_docs where col = 'settings' and id = 'app';
  select data into u  from public.dge_docs where col = 'users'    and id = v_code;
  if not (st is null or (u is not null and coalesce(u ->> 'uid', '') = '' and coalesce(u ->> 'k', '0') = v_k)) then
    return jsonb_build_object('ok', false, 'code', 'auth/operation-not-allowed');
  end if;
  insert into public.dge_logins (email, pin_hash)
  values (v_email, extensions.crypt(p_pin, extensions.gen_salt('bf', 8)))
  returning uid into v_uid;
  return jsonb_build_object('ok', true, 'email', v_email, 'uid', v_uid, 'token', public.dge_new_session(v_email, v_uid));
end $$;

create or replace function public.dge_change_pin(p_token text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_email text;
  v_th    text := encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
begin
  select email into v_email from public.dge_sessions where token_hash = v_th and expires_at > now();
  if v_email is null then
    return jsonb_build_object('ok', false, 'code', 'auth/requires-recent-login', 'message', 'Please log in again.');
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{6}$' or p_pin = '456987' or p_pin ~ '^(.)\1{5}$'
     or p_pin in ('123456', '654321', '012345', '098765') then
    return jsonb_build_object('ok', false, 'code', 'auth/weak-password', 'message', 'Too easy – choose a different 6-digit PIN');
  end if;
  update public.dge_logins
     set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf', 8)), pin_changed_at = now(), failed = 0, locked_until = null
   where email = v_email;
  delete from public.dge_sessions where email = v_email and token_hash <> v_th;   -- sign out other phones
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.dge_whoami(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public, extensions as $$
declare v_email text; v_uid uuid;
begin
  if p_token is null or length(p_token) not between 32 and 128 then return null; end if;
  select email, uid into v_email, v_uid from public.dge_sessions
   where token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex') and expires_at > now();
  if v_email is null then return null; end if;
  return jsonb_build_object('email', v_email, 'uid', v_uid);
end $$;

create or replace function public.dge_sign_out(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from public.dge_sessions where token_hash = encode(extensions.digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return jsonb_build_object('ok', true);
end $$;

-- ---------- 5. Who may call what ----------
-- Supabase gives anon/authenticated EXECUTE on new functions by default: take it away first.
revoke execute on function
  public.dge_str(jsonb, int), public.dge_num(jsonb, numeric, numeric), public.dge_changed(jsonb, jsonb),
  public.dge_keys(jsonb), public.dge_apply(jsonb, jsonb, boolean, bigint), public.dge_ctx(text),
  public.dge_can_see(jsonb, jsonb), public.dge_valid_enq(jsonb),
  public.dge_allow_write(jsonb, text, text, boolean, jsonb, jsonb), public.dge_new_session(text, uuid),
  public.dge_get(text, text, text), public.dge_query(text, text, jsonb, jsonb, int, text, text),
  public.dge_write(text, jsonb), public.dge_sign_in(text, text), public.dge_create_login(text, text),
  public.dge_change_pin(text, text), public.dge_whoami(text), public.dge_sign_out(text)
from public, anon, authenticated;

-- only the app's entry points are callable from the browser
grant execute on function
  public.dge_get(text, text, text), public.dge_query(text, text, jsonb, jsonb, int, text, text),
  public.dge_write(text, jsonb), public.dge_sign_in(text, text), public.dge_create_login(text, text),
  public.dge_change_pin(text, text), public.dge_whoami(text), public.dge_sign_out(text)
to anon, authenticated;

notify pgrst, 'reload schema';
