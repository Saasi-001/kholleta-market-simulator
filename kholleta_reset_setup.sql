-- KHOLLETA FOUR-PAGE RESET + DATABASE SETUP
-- Preserves auth.users and public.profiles (including existing balances).
-- Replaces only the old P2P/cashier transaction objects.
-- Run the ENTIRE script once in Supabase SQL Editor as project owner.

begin;

-- Remove previous app-specific functions and tables only. User accounts/profiles are kept.
drop function if exists public.p2p_take_offer(uuid,numeric,text,text) cascade;
drop function if exists public.p2p_confirm_trade(uuid) cascade;
drop function if exists public.p2p_cancel_trade(uuid) cascade;
drop function if exists public.admin_adjust_own_wallet(text,numeric,text) cascade;
drop function if exists public.admin_set_user_status(uuid,text) cascade;
drop function if exists public.admin_set_user_role(uuid,text) cascade;
drop function if exists public.is_kholleta_admin() cascade;
drop table if exists public.p2p_trades cascade;
drop table if exists public.p2p_offers cascade;
drop table if exists public.cashier_transactions cascade;

-- Existing profiles table is the real-wallet source of truth.
alter table public.profiles add column if not exists balance numeric(14,2) not null default 0;
alter table public.profiles add column if not exists role text not null default 'trader';
alter table public.profiles add column if not exists status text not null default 'active';
alter table public.profiles add column if not exists full_name text;
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists created_at timestamptz not null default now();
update public.profiles set balance=0 where balance is null;
alter table public.profiles alter column balance type numeric(14,2) using coalesce(balance,0)::numeric(14,2);
alter table public.profiles alter column balance set default 0;
alter table public.profiles alter column balance set not null;

create table public.cashier_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  user_email text,
  user_name text,
  tx_type text not null check (tx_type in ('DEPOSIT','WITHDRAW','P2P_BUY','P2P_SELL')),
  amount numeric(14,2) not null check (amount > 0),
  balance_after numeric(14,2) not null,
  note text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
create index cashier_transactions_user_time_idx on public.cashier_transactions(user_id,created_at desc);
create index cashier_transactions_time_idx on public.cashier_transactions(created_at desc);

create table public.p2p_offers (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  owner_name text not null,
  offer_type text not null check (offer_type in ('buy','sell')),
  network text not null check (network in ('MTN','AIRTEL')),
  phone text not null,
  amount_total numeric(14,2) not null check (amount_total > 0),
  amount_remaining numeric(14,2) not null check (amount_remaining >= 0),
  rate_ugx numeric(14,2) not null check (rate_ugx > 0),
  min_usd numeric(14,2) not null check (min_usd > 0),
  max_usd numeric(14,2) not null check (max_usd >= min_usd),
  status text not null default 'open' check (status in ('open','closed','cancelled')),
  created_at timestamptz not null default now(),
  constraint p2p_offer_limits check (max_usd <= amount_total)
);
create index p2p_offers_open_idx on public.p2p_offers(status,offer_type,created_at desc);

create table public.p2p_trades (
  id uuid primary key default gen_random_uuid(),
  offer_id uuid not null references public.p2p_offers(id),
  maker_id uuid not null references auth.users(id),
  taker_id uuid not null references auth.users(id),
  offer_type text not null check (offer_type in ('buy','sell')),
  maker_name text not null,
  taker_name text not null,
  maker_network text not null check (maker_network in ('MTN','AIRTEL')),
  maker_phone text not null,
  taker_network text not null check (taker_network in ('MTN','AIRTEL')),
  taker_phone text not null,
  amount_usd numeric(14,2) not null check (amount_usd > 0),
  amount_ugx numeric(18,2) not null check (amount_ugx > 0),
  status text not null default 'payment_pending' check (status in ('payment_pending','completed','cancelled')),
  created_at timestamptz not null default now(),
  completed_at timestamptz
);
create index p2p_trades_maker_idx on public.p2p_trades(maker_id,created_at desc);
create index p2p_trades_taker_idx on public.p2p_trades(taker_id,created_at desc);

alter table public.profiles enable row level security;
alter table public.cashier_transactions enable row level security;
alter table public.p2p_offers enable row level security;
alter table public.p2p_trades enable row level security;

-- Helper is SECURITY DEFINER to avoid recursive profile RLS checks.
create or replace function public.is_kholleta_admin()
returns boolean language sql stable security definer set search_path=public,auth as $$
  select exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='admin' and coalesce(p.status,'active')='active');
$$;
revoke all on function public.is_kholleta_admin() from public;
grant execute on function public.is_kholleta_admin() to authenticated;

-- Remove legacy profile policies so old permissive update rules cannot bypass the wallet RPCs.
do $$ declare pol record; begin for pol in select policyname from pg_policies where schemaname='public' and tablename='profiles' loop execute format('drop policy %I on public.profiles',pol.policyname); end loop; end $$;
-- Profile access: traders see their own row; admins can view all profiles. No client-side profile updates.
drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using (id=auth.uid() or public.is_kholleta_admin());
revoke insert,update,delete on public.profiles from authenticated;

-- No browser-side balance or role/status updates. All money changes go through RPCs.
drop policy if exists cashier_transactions_admin_read on public.cashier_transactions;
create policy cashier_transactions_admin_read on public.cashier_transactions for select to authenticated
using (public.is_kholleta_admin());

create policy p2p_offers_read_open_or_owner on public.p2p_offers for select to authenticated
using (status='open' or owner_id=auth.uid());
create policy p2p_offers_insert_own on public.p2p_offers for insert to authenticated
with check (owner_id=auth.uid());
create policy p2p_offers_update_own on public.p2p_offers for update to authenticated
using (owner_id=auth.uid()) with check (owner_id=auth.uid());
create policy p2p_trades_read_participant on public.p2p_trades for select to authenticated
using (maker_id=auth.uid() or taker_id=auth.uid());

-- Admin direct deposit/withdraw: only the signed-in admin's own wallet.
create or replace function public.admin_adjust_own_wallet(p_action text,p_amount numeric,p_note text default null)
returns numeric language plpgsql security definer set search_path=public,auth as $$
declare v_user uuid:=auth.uid(); v_balance numeric; v_new numeric; v_profile public.profiles%rowtype;
begin
  if v_user is null then raise exception 'Sign in required'; end if;
  select * into v_profile from public.profiles where id=v_user for update;
  if not found or v_profile.role<>'admin' or coalesce(v_profile.status,'active')<>'active' then raise exception 'Administrator access required'; end if;
  if p_action not in ('DEPOSIT','WITHDRAW') then raise exception 'Choose DEPOSIT or WITHDRAW'; end if;
  if p_amount is null or p_amount<=0 then raise exception 'Enter a valid positive amount'; end if;
  v_balance:=coalesce(v_profile.balance,0);
  if p_action='WITHDRAW' and p_amount>v_balance then raise exception 'Insufficient administrator wallet balance'; end if;
  v_new:=round(case when p_action='DEPOSIT' then v_balance+p_amount else v_balance-p_amount end,2);
  update public.profiles set balance=v_new where id=v_user;
  insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
  values(v_user,v_profile.email,v_profile.full_name,p_action,round(p_amount,2),v_new,coalesce(p_note,'Admin self-service adjustment'),v_user);
  return v_new;
end; $$;

-- Admin-only user role/status controls. No arbitrary balance editing.
create or replace function public.admin_set_user_status(p_user_id uuid,p_status text)
returns void language plpgsql security definer set search_path=public,auth as $$
begin
  if not public.is_kholleta_admin() then raise exception 'Administrator access required'; end if;
  if p_status not in ('active','suspended') then raise exception 'Invalid account status'; end if;
  if p_user_id=auth.uid() and p_status='suspended' then raise exception 'You cannot suspend your own admin account'; end if;
  update public.profiles set status=p_status where id=p_user_id;
  if not found then raise exception 'User profile not found'; end if;
end; $$;
create or replace function public.admin_set_user_role(p_user_id uuid,p_role text)
returns void language plpgsql security definer set search_path=public,auth as $$
begin
  if not public.is_kholleta_admin() then raise exception 'Administrator access required'; end if;
  if p_role not in ('admin','trader') then raise exception 'Invalid account role'; end if;
  if p_user_id=auth.uid() and p_role<>'admin' then raise exception 'You cannot remove your own admin role'; end if;
  update public.profiles set role=p_role where id=p_user_id;
  if not found then raise exception 'User profile not found'; end if;
end; $$;

-- P2P offer creation/acceptance/settlement.
create or replace function public.p2p_take_offer(p_offer_id uuid,p_amount_usd numeric,p_taker_network text,p_taker_phone text)
returns uuid language plpgsql security definer set search_path=public,auth as $$
declare o public.p2p_offers%rowtype; v_id uuid; v_name text;
begin
  if auth.uid() is null then raise exception 'Sign in required'; end if;
  if p_amount_usd is null or p_amount_usd<=0 then raise exception 'Enter a valid USD amount'; end if;
  if upper(p_taker_network) not in ('MTN','AIRTEL') then raise exception 'Choose MTN or Airtel'; end if;
  if length(trim(coalesce(p_taker_phone,'')))<9 then raise exception 'Enter a valid mobile-money number'; end if;
  select * into o from public.p2p_offers where id=p_offer_id for update;
  if not found or o.status<>'open' then raise exception 'Offer is no longer available'; end if;
  if o.owner_id=auth.uid() then raise exception 'You cannot accept your own offer'; end if;
  if p_amount_usd<o.min_usd or p_amount_usd>o.max_usd or p_amount_usd>o.amount_remaining then raise exception 'Amount is outside this offer limit'; end if;
  select coalesce(full_name,email,'Trader') into v_name from public.profiles where id=auth.uid();
  update public.p2p_offers set amount_remaining=amount_remaining-p_amount_usd,
    status=case when amount_remaining-p_amount_usd=0 then 'closed' else 'open' end where id=p_offer_id;
  insert into public.p2p_trades(offer_id,maker_id,taker_id,offer_type,maker_name,taker_name,maker_network,maker_phone,taker_network,taker_phone,amount_usd,amount_ugx)
  values(o.id,o.owner_id,auth.uid(),o.offer_type,o.owner_name,coalesce(v_name,'Trader'),o.network,o.phone,upper(p_taker_network),trim(p_taker_phone),round(p_amount_usd,2),round(p_amount_usd*o.rate_ugx,2)) returning id into v_id;
  return v_id;
end; $$;

create or replace function public.p2p_confirm_trade(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype; v_balance numeric; v_payer uuid; v_receiver uuid; v_confirmer uuid; v_receiver_count integer;
begin
  if auth.uid() is null then raise exception 'Sign in required'; end if;
  select * into t from public.p2p_trades where id=p_trade_id for update;
  if not found then raise exception 'Transaction not found'; end if;
  if t.status<>'payment_pending' then raise exception 'Transaction is not pending'; end if;
  if t.offer_type='buy' then v_confirmer:=t.taker_id; v_payer:=t.taker_id; v_receiver:=t.maker_id;
  else v_confirmer:=t.maker_id; v_payer:=t.maker_id; v_receiver:=t.taker_id; end if;
  if auth.uid()<>v_confirmer then raise exception 'Only the mobile-money recipient can confirm receipt'; end if;
  select coalesce(balance,0) into v_balance from public.profiles where id=v_payer for update;
  if not found then raise exception 'Payer profile not found'; end if;
  if v_balance<t.amount_usd then raise exception 'USD seller has insufficient balance'; end if;
  perform 1 from public.profiles where id=v_receiver for update;
  if not found then raise exception 'Receiving account profile not found'; end if;
  update public.profiles set balance=coalesce(balance,0)-t.amount_usd where id=v_payer;
  update public.profiles set balance=coalesce(balance,0)+t.amount_usd where id=v_receiver;
  insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
  select p.id,p.email,p.full_name,case when p.id=v_payer then 'P2P_SELL' else 'P2P_BUY' end,t.amount_usd,p.balance,
         'P2P settlement '||p_trade_id,auth.uid()
  from public.profiles p where p.id in (v_payer,v_receiver);
  update public.p2p_trades set status='completed',completed_at=now() where id=p_trade_id;
end; $$;

create or replace function public.p2p_cancel_trade(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype;
begin
  if auth.uid() is null then raise exception 'Sign in required'; end if;
  select * into t from public.p2p_trades where id=p_trade_id for update;
  if not found then raise exception 'Transaction not found'; end if;
  if t.maker_id<>auth.uid() then raise exception 'Only the offer owner can reject this request'; end if;
  if t.status<>'payment_pending' then raise exception 'Transaction is not pending'; end if;
  update public.p2p_trades set status='cancelled' where id=p_trade_id;
  update public.p2p_offers set amount_remaining=amount_remaining+t.amount_usd,status='open' where id=t.offer_id;
end; $$;

revoke all on function public.admin_adjust_own_wallet(text,numeric,text) from public;
revoke all on function public.admin_set_user_status(uuid,text) from public;
revoke all on function public.admin_set_user_role(uuid,text) from public;
revoke all on function public.p2p_take_offer(uuid,numeric,text,text) from public;
revoke all on function public.p2p_confirm_trade(uuid) from public;
revoke all on function public.p2p_cancel_trade(uuid) from public;
grant execute on function public.admin_adjust_own_wallet(text,numeric,text) to authenticated;
grant execute on function public.admin_set_user_status(uuid,text) to authenticated;
grant execute on function public.admin_set_user_role(uuid,text) to authenticated;
grant execute on function public.p2p_take_offer(uuid,numeric,text,text) to authenticated;
grant execute on function public.p2p_confirm_trade(uuid) to authenticated;
grant execute on function public.p2p_cancel_trade(uuid) to authenticated;
grant select,insert,update on public.p2p_offers to authenticated;
grant select on public.p2p_trades to authenticated;
grant select on public.cashier_transactions to authenticated;
grant select on public.profiles to authenticated;

commit;
