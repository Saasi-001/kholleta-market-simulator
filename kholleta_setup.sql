-- KHOLLETA MARKET DATABASE UPDATE
-- Run in Supabase SQL Editor as project owner.
-- Preserves auth.users and public.profiles balances. Recreates only cashier/P2P objects.
-- All real USD movement is server-side; no browser may update profiles.balance directly.

begin;

drop function if exists public.p2p_take_offer(uuid,numeric,text,text) cascade;
drop function if exists public.p2p_accept_trade(uuid) cascade;
drop function if exists public.p2p_mark_paid(uuid) cascade;
drop function if exists public.p2p_release_usd(uuid) cascade;
drop function if exists public.p2p_confirm_trade(uuid) cascade;
drop function if exists public.p2p_cancel_trade(uuid) cascade;
drop function if exists public.transfer_wallet_by_email(text,numeric,text) cascade;
drop function if exists public.admin_transfer_wallet_by_email(text,numeric,text) cascade;
drop function if exists public.admin_adjust_own_wallet(text,numeric,text) cascade;
drop function if exists public.admin_set_user_status(uuid,text) cascade;
drop function if exists public.admin_set_user_role(uuid,text) cascade;
drop function if exists public.is_kholleta_admin() cascade;
drop table if exists public.p2p_trades cascade;
drop table if exists public.p2p_offers cascade;
drop table if exists public.cashier_transactions cascade;

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
  tx_type text not null,
  amount numeric(14,2) not null check(amount>0),
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
  offer_type text not null check(offer_type in ('buy','sell')),
  network text not null check(network in ('MTN','AIRTEL')),
  phone text not null,
  amount_total numeric(14,2) not null check(amount_total>0),
  amount_remaining numeric(14,2) not null check(amount_remaining>=0),
  rate_ugx numeric(14,2) not null check(rate_ugx>0),
  min_usd numeric(14,2) not null check(min_usd>0),
  max_usd numeric(14,2) not null check(max_usd>=min_usd),
  status text not null default 'open' check(status in ('open','closed','cancelled')),
  created_at timestamptz not null default now(),
  constraint p2p_offer_limits check(max_usd<=amount_total)
);
create index p2p_offers_open_idx on public.p2p_offers(status,offer_type,created_at desc);

create table public.p2p_trades (
  id uuid primary key default gen_random_uuid(),
  offer_id uuid not null references public.p2p_offers(id),
  maker_id uuid not null references auth.users(id),
  taker_id uuid not null references auth.users(id),
  offer_type text not null check(offer_type in ('buy','sell')),
  maker_name text not null,
  taker_name text not null,
  maker_network text not null check(maker_network in ('MTN','AIRTEL')),
  maker_phone text not null,
  taker_network text not null check(taker_network in ('MTN','AIRTEL')),
  taker_phone text not null,
  amount_usd numeric(14,2) not null check(amount_usd>0),
  amount_ugx numeric(18,2) not null check(amount_ugx>0),
  status text not null default 'requested'
    check(status in ('requested','accepted','payment_sent','completed','cancelled')),
  escrow_seller_id uuid references auth.users(id),
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  paid_at timestamptz,
  completed_at timestamptz
);
create index p2p_trades_maker_idx on public.p2p_trades(maker_id,created_at desc);
create index p2p_trades_taker_idx on public.p2p_trades(taker_id,created_at desc);

alter table public.profiles enable row level security;
alter table public.cashier_transactions enable row level security;
alter table public.p2p_offers enable row level security;
alter table public.p2p_trades enable row level security;

create or replace function public.is_kholleta_admin()
returns boolean language sql stable security definer set search_path=public,auth as $$
 select exists(select 1 from public.profiles p where p.id=auth.uid()
   and p.role='admin' and coalesce(p.status,'active')='active');
$$;
revoke all on function public.is_kholleta_admin() from public;
grant execute on function public.is_kholleta_admin() to authenticated;

do $$ declare pol record; begin
 for pol in select policyname from pg_policies where schemaname='public' and tablename='profiles'
 loop execute format('drop policy %I on public.profiles',pol.policyname); end loop;
end $$;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using(id=auth.uid() or public.is_kholleta_admin());
revoke insert,update,delete on public.profiles from anon,authenticated;

create policy cashier_transactions_admin_read on public.cashier_transactions for select to authenticated
using(public.is_kholleta_admin());
create policy p2p_offers_read_open_or_owner on public.p2p_offers for select to authenticated
using(status='open' or owner_id=auth.uid());
create policy p2p_offers_insert_own on public.p2p_offers for insert to authenticated
with check(owner_id=auth.uid());
create policy p2p_offers_update_own on public.p2p_offers for update to authenticated
using(owner_id=auth.uid()) with check(owner_id=auth.uid());
create policy p2p_trades_read_participant on public.p2p_trades for select to authenticated
using(maker_id=auth.uid() or taker_id=auth.uid());

-- Admin may add/remove funds from the admin reserve wallet. created_by is explicitly present.
create or replace function public.admin_adjust_own_wallet(p_action text,p_amount numeric,p_note text default null)
returns numeric language plpgsql security definer set search_path=public,auth as $$
declare v_uid uuid:=auth.uid(); v_p public.profiles%rowtype; v_new numeric(14,2);
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 select * into v_p from public.profiles where id=v_uid for update;
 if not found or v_p.role<>'admin' or coalesce(v_p.status,'active')<>'active' then raise exception 'Administrator access required'; end if;
 if p_action not in ('DEPOSIT','WITHDRAW') then raise exception 'Choose DEPOSIT or WITHDRAW'; end if;
 if p_amount is null or p_amount<=0 then raise exception 'Enter a valid positive amount'; end if;
 if p_action='WITHDRAW' and v_p.balance<p_amount then raise exception 'Insufficient administrator reserve balance'; end if;
 v_new:=round(case when p_action='DEPOSIT' then v_p.balance+p_amount else v_p.balance-p_amount end,2);
 update public.profiles set balance=v_new where id=v_uid;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 values(v_uid,v_p.email,v_p.full_name,p_action,round(p_amount,2),v_new,coalesce(p_note,'Admin reserve adjustment'),v_uid);
 return v_new;
end; $$;

-- Normal account-to-account transfer. Sender must own the funds.
create or replace function public.transfer_wallet_by_email(p_to_email text,p_amount numeric,p_note text default null)
returns void language plpgsql security definer set search_path=public,auth as $$
declare v_from uuid:=auth.uid(); v_to uuid; v_from_p public.profiles%rowtype; v_to_p public.profiles%rowtype;
begin
 if v_from is null then raise exception 'Sign in required'; end if;
 if p_amount is null or p_amount<=0 then raise exception 'Enter a valid amount'; end if;
 select * into v_from_p from public.profiles where id=v_from for update;
 select id into v_to from public.profiles where lower(email)=lower(trim(p_to_email));
 if v_to is null then raise exception 'Recipient account was not found'; end if;
 if v_to=v_from then raise exception 'You cannot transfer to yourself'; end if;
 select * into v_to_p from public.profiles where id=v_to for update;
 if coalesce(v_from_p.status,'active')<>'active' or coalesce(v_to_p.status,'active')<>'active' then raise exception 'Both accounts must be active'; end if;
 if v_from_p.balance<p_amount then raise exception 'Insufficient balance'; end if;
 update public.profiles set balance=round(balance-p_amount,2) where id=v_from;
 update public.profiles set balance=round(balance+p_amount,2) where id=v_to;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'TRANSFER_OUT',round(p_amount,2),balance,coalesce(p_note,'Account transfer to '||p_to_email),v_from
 from public.profiles where id=v_from;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'TRANSFER_IN',round(p_amount,2),balance,coalesce(p_note,'Account transfer from '||v_from_p.email),v_from
 from public.profiles where id=v_to;
end; $$;

-- Admin reserve -> trader account transfer.
create or replace function public.admin_transfer_wallet_by_email(p_to_email text,p_amount numeric,p_note text default null)
returns void language plpgsql security definer set search_path=public,auth as $$
declare v_admin uuid:=auth.uid(); v_to uuid; v_admin_p public.profiles%rowtype;
begin
 if not public.is_kholleta_admin() then raise exception 'Administrator access required'; end if;
 if p_amount is null or p_amount<=0 then raise exception 'Enter a valid amount'; end if;
 select * into v_admin_p from public.profiles where id=v_admin for update;
 select id into v_to from public.profiles where lower(email)=lower(trim(p_to_email));
 if v_to is null then raise exception 'Recipient account was not found'; end if;
 if v_to=v_admin then raise exception 'Choose a different account'; end if;
 if v_admin_p.balance<p_amount then raise exception 'Insufficient admin reserve balance'; end if;
 perform 1 from public.profiles where id=v_to and coalesce(status,'active')='active' for update;
 if not found then raise exception 'Recipient account is missing or suspended'; end if;
 update public.profiles set balance=round(balance-p_amount,2) where id=v_admin;
 update public.profiles set balance=round(balance+p_amount,2) where id=v_to;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'RESERVE_TRANSFER_OUT',round(p_amount,2),balance,coalesce(p_note,'Admin reserve transfer to '||p_to_email),v_admin
 from public.profiles where id=v_admin;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'RESERVE_TRANSFER_IN',round(p_amount,2),balance,coalesce(p_note,'Admin reserve transfer from admin'),v_admin
 from public.profiles where id=v_to;
end; $$;

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

-- Creating a request does not reserve the offer. The owner must accept it.
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
 if o.owner_id=auth.uid() then raise exception 'You cannot request your own offer'; end if;
 if p_amount_usd<o.min_usd or p_amount_usd>o.max_usd or p_amount_usd>o.amount_remaining then raise exception 'Amount is outside this offer limit'; end if;
 select coalesce(full_name,email,'Trader') into v_name from public.profiles where id=auth.uid() and coalesce(status,'active')='active';
 if v_name is null then raise exception 'Active trader profile required'; end if;
 insert into public.p2p_trades(offer_id,maker_id,taker_id,offer_type,maker_name,taker_name,maker_network,maker_phone,taker_network,taker_phone,amount_usd,amount_ugx)
 values(o.id,o.owner_id,auth.uid(),o.offer_type,o.owner_name,v_name,o.network,o.phone,upper(p_taker_network),trim(p_taker_phone),round(p_amount_usd,2),round(p_amount_usd*o.rate_ugx,2))
 returning id into v_id;
 return v_id;
end; $$;

-- Owner acceptance reserves the USD seller's funds in escrow by debiting their wallet.
create or replace function public.p2p_accept_trade(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype; o public.p2p_offers%rowtype; v_seller uuid; v_p public.profiles%rowtype;
begin
 select * into t from public.p2p_trades where id=p_trade_id for update;
 if not found then raise exception 'Request not found'; end if;
 if auth.uid()<>t.maker_id then raise exception 'Only the offer owner can accept'; end if;
 if t.status<>'requested' then raise exception 'Request is not awaiting acceptance'; end if;
 select * into o from public.p2p_offers where id=t.offer_id for update;
 if not found or o.status not in ('open','closed') or o.amount_remaining<t.amount_usd then
   raise exception 'Offer no longer has enough available USD';
 end if;
 v_seller:=case when t.offer_type='buy' then t.maker_id else t.taker_id end;
 select * into v_p from public.profiles where id=v_seller for update;
 if not found or coalesce(v_p.status,'active')<>'active' then raise exception 'USD seller account is unavailable'; end if;
 if v_p.balance<t.amount_usd then raise exception 'USD seller has insufficient available balance'; end if;
 update public.profiles set balance=round(balance-t.amount_usd,2) where id=v_seller;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'P2P_ESCROW_HOLD',t.amount_usd,balance,'USD reserved for P2P trade '||t.id,auth.uid()
 from public.profiles where id=v_seller;
 update public.p2p_offers set amount_remaining=amount_remaining-t.amount_usd,
   status=case when amount_remaining-t.amount_usd<=0 then 'closed' else 'open' end where id=t.offer_id;
 update public.p2p_trades set status='accepted',escrow_seller_id=v_seller,accepted_at=now() where id=t.id;
end; $$;

-- Only the UGX payer can mark that the transfer was sent.
create or replace function public.p2p_mark_paid(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype; v_payer uuid;
begin
 select * into t from public.p2p_trades where id=p_trade_id for update;
 if not found then raise exception 'Trade not found'; end if;
 if t.status<>'accepted' then raise exception 'Trade is not awaiting payment'; end if;
 v_payer:=case when t.offer_type='buy' then t.taker_id else t.maker_id end;
 if auth.uid()<>v_payer then raise exception 'Only the UGX payer can mark payment as sent'; end if;
 update public.p2p_trades set status='payment_sent',paid_at=now() where id=t.id;
end; $$;

-- Only the USD seller can release escrow after independently verifying mobile-money receipt.
create or replace function public.p2p_release_usd(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype; v_seller uuid; v_buyer uuid; v_new numeric;
begin
 select * into t from public.p2p_trades where id=p_trade_id for update;
 if not found then raise exception 'Trade not found'; end if;
 if t.status<>'payment_sent' then raise exception 'Payer has not marked payment as sent'; end if;
 v_seller:=case when t.offer_type='buy' then t.maker_id else t.taker_id end;
 v_buyer:=case when t.offer_type='buy' then t.taker_id else t.maker_id end;
 if auth.uid()<>v_seller then raise exception 'Only the USD seller can release the funds'; end if;
 update public.profiles set balance=round(balance+t.amount_usd,2) where id=v_buyer;
 if not found then raise exception 'USD buyer account not found'; end if;
 select balance into v_new from public.profiles where id=v_buyer;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'P2P_RELEASE',t.amount_usd,balance,'USD released from P2P trade '||t.id,auth.uid()
 from public.profiles where id=v_buyer;
 update public.p2p_trades set status='completed',completed_at=now() where id=t.id;
end; $$;

-- Reject/withdraw only before acceptance. Accepted escrow cannot be cancelled after payment flow starts.
create or replace function public.p2p_cancel_trade(p_trade_id uuid)
returns void language plpgsql security definer set search_path=public,auth as $$
declare t public.p2p_trades%rowtype;
begin
 select * into t from public.p2p_trades where id=p_trade_id for update;
 if not found then raise exception 'Trade not found'; end if;
 if t.status<>'requested' then raise exception 'Only requests not yet accepted can be cancelled'; end if;
 if auth.uid() not in (t.maker_id,t.taker_id) then raise exception 'Not a trade participant'; end if;
 update public.p2p_trades set status='cancelled' where id=t.id;
end; $$;

revoke all on function public.admin_adjust_own_wallet(text,numeric,text) from public;
revoke all on function public.transfer_wallet_by_email(text,numeric,text) from public;
revoke all on function public.admin_transfer_wallet_by_email(text,numeric,text) from public;
revoke all on function public.admin_set_user_status(uuid,text) from public;
revoke all on function public.admin_set_user_role(uuid,text) from public;
revoke all on function public.p2p_take_offer(uuid,numeric,text,text) from public;
revoke all on function public.p2p_accept_trade(uuid) from public;
revoke all on function public.p2p_mark_paid(uuid) from public;
revoke all on function public.p2p_release_usd(uuid) from public;
revoke all on function public.p2p_cancel_trade(uuid) from public;

grant execute on function public.admin_adjust_own_wallet(text,numeric,text) to authenticated;
grant execute on function public.transfer_wallet_by_email(text,numeric,text) to authenticated;
grant execute on function public.admin_transfer_wallet_by_email(text,numeric,text) to authenticated;
grant execute on function public.admin_set_user_status(uuid,text) to authenticated;
grant execute on function public.admin_set_user_role(uuid,text) to authenticated;
grant execute on function public.p2p_take_offer(uuid,numeric,text,text) to authenticated;
grant execute on function public.p2p_accept_trade(uuid) to authenticated;
grant execute on function public.p2p_mark_paid(uuid) to authenticated;
grant execute on function public.p2p_release_usd(uuid) to authenticated;
grant execute on function public.p2p_cancel_trade(uuid) to authenticated;
grant select,insert,update on public.p2p_offers to authenticated;
grant select on public.p2p_trades,public.cashier_transactions,public.profiles to authenticated;

commit;
