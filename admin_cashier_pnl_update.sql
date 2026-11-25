-- KHOLLETA ADMIN CASHIER VISIBILITY + RESERVE P&L
-- Safe additive migration. Does not drop or recreate user, offer, trade, or ledger tables.
begin;

-- Allow an authenticated active admin to view every offer and every P2P request.
drop policy if exists p2p_offers_admin_read_all on public.p2p_offers;
create policy p2p_offers_admin_read_all on public.p2p_offers
for select to authenticated using (public.is_kholleta_admin());

drop policy if exists p2p_trades_admin_read_all on public.p2p_trades;
create policy p2p_trades_admin_read_all on public.p2p_trades
for select to authenticated using (public.is_kholleta_admin());

grant select on public.p2p_offers, public.p2p_trades, public.cashier_transactions, public.profiles to authenticated;

-- Add explicit reserve-side ledger events so the admin graph can distinguish:
-- trader losses received (positive reserve P&L) and winning profit payouts (negative P&L).
create or replace function public.simulator_settle_trade(p_position_id uuid,p_won boolean)
returns numeric language plpgsql security definer set search_path=public,auth as $$
declare
  v_uid uuid:=auth.uid();
  v_pos public.simulator_open_positions%rowtype;
  v_user public.profiles%rowtype;
  v_admin public.profiles%rowtype;
  v_new numeric(14,2);
  v_admin_new numeric(14,2);
  v_profit numeric(14,2);
begin
  if v_uid is null then raise exception 'Sign in required'; end if;
  select * into v_pos from public.simulator_open_positions where id=p_position_id for update;
  if not found or v_pos.user_id<>v_uid or v_pos.status<>'open' then
    raise exception 'Open simulator position not found';
  end if;
  select * into v_admin from public.profiles
    where role='admin' and coalesce(status,'active')='active'
    order by created_at asc limit 1 for update;
  if not found then raise exception 'Admin reserve account is not configured'; end if;
  if v_admin.id=v_uid then raise exception 'Admin reserve account cannot settle trader contracts'; end if;
  select * into v_user from public.profiles where id=v_uid for update;
  if not found or coalesce(v_user.status,'active')<>'active' then
    raise exception 'Active trader account required';
  end if;

  if p_won then
    v_profit:=round(v_pos.payout-v_pos.stake,2);
    if v_admin.balance<v_profit then raise exception 'Admin reserve cannot cover this simulated win yet'; end if;
    v_new:=round(v_user.balance+v_pos.payout,2);
    v_admin_new:=round(v_admin.balance-v_profit,2);
    update public.profiles set balance=v_new where id=v_uid;
    update public.profiles set balance=v_admin_new where id=v_admin.id;

    insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
    values(v_uid,v_user.email,v_user.full_name,'SIM_TRADE_WIN',v_pos.payout,v_new,
      'Virtual simulator winning payout; reserve funded profit',v_admin.id);

    insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
    values(v_admin.id,v_admin.email,v_admin.full_name,'RESERVE_TRADE_PAYOUT',v_profit,v_admin_new,
      'Reserve paid winning profit for trader '||coalesce(v_user.email,v_uid::text),v_uid);
  else
    v_new:=v_user.balance;
    v_admin_new:=round(v_admin.balance+v_pos.stake,2);
    update public.profiles set balance=v_admin_new where id=v_admin.id;

    insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
    values(v_uid,v_user.email,v_user.full_name,'SIM_TRADE_LOSS',v_pos.stake,v_new,
      'Virtual simulator loss transferred to admin reserve',v_admin.id);

    insert into public.cashier_transactions(user_id,user_email,user_name,tx_type,amount,balance_after,note,created_by)
    values(v_admin.id,v_admin.email,v_admin.full_name,'RESERVE_TRADE_LOSS',v_pos.stake,v_admin_new,
      'Reserve received simulated loss from trader '||coalesce(v_user.email,v_uid::text),v_uid);
  end if;

  update public.simulator_open_positions set status='settled',settled_at=now() where id=v_pos.id;
  return v_new;
end; $$;

revoke all on function public.simulator_settle_trade(uuid,boolean) from public;
grant execute on function public.simulator_settle_trade(uuid,boolean) to authenticated;

commit;
