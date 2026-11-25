-- NON-DESTRUCTIVE UPDATE for an already-installed Kholleta project.
-- Adds virtual Real-account simulator settlement and changes P2P contact metadata
-- to game tags. Does not drop existing offers, trades, or cashier history.
begin;

-- Migrate old mobile-money labels to the simulator-only GAME channel.
do $$ declare r record; begin
 for r in
  select conrelid::regclass as tbl, conname
  from pg_constraint
  where conrelid in ('public.p2p_offers'::regclass,'public.p2p_trades'::regclass)
    and contype='c' and pg_get_constraintdef(oid) ilike '%network%'
 loop execute format('alter table %s drop constraint %I',r.tbl,r.conname); end loop;
end $$;
update public.p2p_offers set network='GAME',phone='PLAYER-'||left(owner_id::text,8);
update public.p2p_trades set maker_network='GAME',taker_network='GAME',maker_phone='PLAYER-'||left(maker_id::text,8),taker_phone='PLAYER-'||left(taker_id::text,8);
alter table public.p2p_offers add constraint p2p_offers_network_game_check check(network='GAME');
alter table public.p2p_trades add constraint p2p_trades_maker_network_game_check check(maker_network='GAME');
alter table public.p2p_trades add constraint p2p_trades_taker_network_game_check check(taker_network='GAME');

create table if not exists public.simulator_open_positions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  stake numeric(14,2) not null check(stake>=0.35 and stake<=10000),
  payout numeric(14,2) not null check(payout>=stake),
  status text not null default 'open' check(status in ('open','settled')),
  created_at timestamptz not null default now(),
  settled_at timestamptz
);
create index if not exists simulator_open_positions_user_idx on public.simulator_open_positions(user_id,status);
revoke all on public.simulator_open_positions from anon,authenticated;

create or replace function public.admin_adjust_own_wallet(p_action text,p_amount numeric,p_note text default null)
returns numeric language plpgsql security definer set search_path=public,auth as $$
declare v_uid uuid:=auth.uid(); v_p public.profiles%rowtype; v_new numeric(14,2); v_reserved numeric(14,2):=0;
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 select * into v_p from public.profiles where id=v_uid for update;
 if not found or v_p.role<>'admin' or coalesce(v_p.status,'active')<>'active' then raise exception 'Administrator access required'; end if;
 if p_action not in ('DEPOSIT','WITHDRAW') then raise exception 'Choose DEPOSIT or WITHDRAW'; end if;
 if p_amount is null or p_amount<=0 then raise exception 'Enter a valid positive amount'; end if;
 if p_action='WITHDRAW' then
   if v_p.balance<p_amount then raise exception 'Insufficient administrator reserve balance'; end if;
   select coalesce(sum(payout-stake),0) into v_reserved from public.simulator_open_positions where status='open';
   if v_p.balance-p_amount<v_reserved then raise exception 'Those funds are reserved for open simulator contracts'; end if;
 end if;
 v_new:=round(case when p_action='DEPOSIT' then v_p.balance+p_amount else v_p.balance-p_amount end,2);
 update public.profiles set balance=v_new where id=v_uid;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 values(v_uid,v_p.email,v_p.full_name,p_action,round(p_amount,2),v_new,coalesce(p_note,'Admin reserve adjustment'),v_uid);
 return v_new;
end; $$;

-- Normal account-to-account transfer. Sender must own the funds.
create or replace function public.transfer_wallet_by_email(p_to_email text,p_amount numeric,p_note text default null)
returns void language plpgsql security definer set search_path=public,auth as $$
declare v_from uuid:=auth.uid(); v_to uuid; v_from_p public.profiles%rowtype; v_to_p public.profiles%rowtype; v_reserved numeric(14,2):=0;
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
 if v_from_p.role='admin' then
   select coalesce(sum(payout-stake),0) into v_reserved from public.simulator_open_positions where status='open';
   if v_from_p.balance-p_amount<v_reserved then raise exception 'Those funds are reserved for open simulator contracts'; end if;
 end if;
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
declare v_admin uuid:=auth.uid(); v_to uuid; v_admin_p public.profiles%rowtype; v_reserved numeric(14,2):=0;
begin
 if not public.is_kholleta_admin() then raise exception 'Administrator access required'; end if;
 if p_amount is null or p_amount<=0 then raise exception 'Enter a valid amount'; end if;
 select * into v_admin_p from public.profiles where id=v_admin for update;
 select id into v_to from public.profiles where lower(email)=lower(trim(p_to_email));
 if v_to is null then raise exception 'Recipient account was not found'; end if;
 if v_to=v_admin then raise exception 'Choose a different account'; end if;
 if v_admin_p.balance<p_amount then raise exception 'Insufficient admin reserve balance'; end if;
 select coalesce(sum(payout-stake),0) into v_reserved from public.simulator_open_positions where status='open';
 if v_admin_p.balance-p_amount<v_reserved then raise exception 'Those funds are reserved for open simulator contracts'; end if;
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


create or replace function public.p2p_take_offer(p_offer_id uuid,p_amount_usd numeric,p_taker_network text,p_taker_phone text)
returns uuid language plpgsql security definer set search_path=public,auth as $$
declare o public.p2p_offers%rowtype; v_id uuid; v_name text;
begin
 if auth.uid() is null then raise exception 'Sign in required'; end if;
 if p_amount_usd is null or p_amount_usd<=0 then raise exception 'Enter a valid USD amount'; end if;
 if upper(p_taker_network)<>'GAME' then raise exception 'Choose the GAME channel'; end if;
 if length(trim(coalesce(p_taker_phone,'')))<3 then raise exception 'Enter a valid player tag'; end if;
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

create or replace function public.simulator_open_trade(p_amount numeric,p_payout numeric)
returns uuid language plpgsql security definer set search_path=public,auth as $$
declare v_uid uuid:=auth.uid(); v_user public.profiles%rowtype; v_admin public.profiles%rowtype; v_id uuid; v_reserved numeric(14,2);
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 if p_amount is null or p_amount<0.35 or p_amount>10000 then raise exception 'Stake must be between $0.35 and $10,000'; end if;
 if p_payout is null or p_payout<p_amount then raise exception 'Invalid potential payout'; end if;
 select * into v_admin from public.profiles where role='admin' and coalesce(status,'active')='active' order by created_at asc limit 1 for update;
 if not found then raise exception 'Admin reserve account is not configured'; end if;
 if v_admin.id=v_uid then raise exception 'Admin reserve account cannot place trader contracts'; end if;
 select coalesce(sum(payout-stake),0) into v_reserved from public.simulator_open_positions where status='open';
 if v_admin.balance-v_reserved<round(p_payout-p_amount,2) then raise exception 'Admin reserve has insufficient funds to cover this potential win'; end if;
 select * into v_user from public.profiles where id=v_uid for update;
 if not found or coalesce(v_user.status,'active')<>'active' then raise exception 'Active trader account required'; end if;
 if v_user.balance<p_amount then raise exception 'Insufficient Real account simulator balance'; end if;
 update public.profiles set balance=round(balance-p_amount,2) where id=v_uid;
 insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
 select id,email,full_name,'SIM_TRADE_STAKE',round(p_amount,2),balance,'Virtual simulator contract stake',v_uid from public.profiles where id=v_uid;
 insert into public.simulator_open_positions(user_id,stake,payout) values(v_uid,round(p_amount,2),round(p_payout,2)) returning id into v_id;
 return v_id;
end; $$;

create or replace function public.simulator_settle_trade(p_position_id uuid,p_won boolean)
returns numeric language plpgsql security definer set search_path=public,auth as $$
declare v_uid uuid:=auth.uid(); v_pos public.simulator_open_positions%rowtype; v_user public.profiles%rowtype; v_admin public.profiles%rowtype; v_new numeric(14,2); v_profit numeric(14,2);
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 select * into v_pos from public.simulator_open_positions where id=p_position_id for update;
 if not found or v_pos.user_id<>v_uid or v_pos.status<>'open' then raise exception 'Open simulator position not found'; end if;
 select * into v_admin from public.profiles where role='admin' and coalesce(status,'active')='active' order by created_at asc limit 1 for update;
 if not found then raise exception 'Admin reserve account is not configured'; end if;
 if v_admin.id=v_uid then raise exception 'Admin reserve account cannot settle trader contracts'; end if;
 select * into v_user from public.profiles where id=v_uid for update;
 if not found or coalesce(v_user.status,'active')<>'active' then raise exception 'Active trader account required'; end if;
 if p_won then
   v_profit:=round(v_pos.payout-v_pos.stake,2);
   if v_admin.balance<v_profit then raise exception 'Admin reserve cannot cover this simulated win yet'; end if;
   v_new:=round(v_user.balance+v_pos.payout,2);
   update public.profiles set balance=v_new where id=v_uid;
   update public.profiles set balance=round(balance-v_profit,2) where id=v_admin.id;
   insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
   values(v_uid,v_user.email,v_user.full_name,'SIM_TRADE_WIN',v_pos.payout,v_new,'Virtual simulator winning payout; reserve funded profit',v_admin.id);
 else
   update public.profiles set balance=round(balance+v_pos.stake,2) where id=v_admin.id;
   v_new:=v_user.balance;
   insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
   values(v_uid,v_user.email,v_user.full_name,'SIM_TRADE_LOSS',v_pos.stake,v_new,'Virtual simulator loss transferred to admin reserve',v_admin.id);
 end if;
 update public.simulator_open_positions set status='settled',settled_at=now() where id=v_pos.id;
 return v_new;
end; $$;

revoke all on function public.admin_adjust_own_wallet(text,numeric,text) from public;
revoke all on function public.transfer_wallet_by_email(text,numeric,text) from public;
revoke all on function public.admin_transfer_wallet_by_email(text,numeric,text) from public;
revoke all on function public.p2p_take_offer(uuid,numeric,text,text) from public;
revoke all on function public.simulator_open_trade(numeric,numeric) from public;
revoke all on function public.simulator_settle_trade(uuid,boolean) from public;
grant execute on function public.admin_adjust_own_wallet(text,numeric,text) to authenticated;
grant execute on function public.transfer_wallet_by_email(text,numeric,text) to authenticated;
grant execute on function public.admin_transfer_wallet_by_email(text,numeric,text) to authenticated;
grant execute on function public.p2p_take_offer(uuid,numeric,text,text) to authenticated;
grant execute on function public.simulator_open_trade(numeric,numeric) to authenticated;
grant execute on function public.simulator_settle_trade(uuid,boolean) to authenticated;
commit;
