KHOLLETA UPDATED FILES

Files:
- index.html: Supabase email confirmation callback returns to login page.
- kholletta.html: cashier shortcut and $10,000 maximum single stake. The synthetic simulator remains demo-only.
- cashier.html: request/accept/mark-paid/release-USD P2P flow and account-to-account transfers.
- admin.html: admin reserve wallet adjustment and reserve-to-user transfer.
- kholleta_setup.sql: Supabase schema, RLS, escrow, wallet transfer and admin RPCs.

DEPLOYMENT
1. Back up your current Supabase project/database first.
2. Run kholleta_setup.sql once in Supabase SQL Editor as project owner.
   IMPORTANT: this setup script drops/recreates the P2P/cashier tables and their records.
   It preserves auth.users and public.profiles, but clears old cashier/P2P transaction history.
3. Upload/replace the four HTML files on your hosting using these exact names:
   index.html, kholletta.html, cashier.html, admin.html.
4. In Supabase Dashboard -> Authentication -> URL Configuration:
   - Set Site URL to your deployed website root.
   - Add the deployed index.html URL to Redirect URLs.
5. Confirm your Supabase email template uses the standard confirmation URL supplied by Supabase.

P2P DIRECTION
- BUY USD: taker sends UGX to offer owner; offer owner is USD seller and releases USD to taker.
- SELL USD: offer owner sends UGX to taker; taker is USD seller and releases USD to offer owner.
- The seller's USD is debited into escrow when the offer owner accepts. It is credited to the buyer only when the seller clicks Verify receipt & release USD.
- If a user marks payment sent but the recipient does not receive it, the trade remains in payment_sent. Admin/manual dispute handling is still required; do not release funds without verifying the mobile-money statement.

LIVE TRADING
This project does not contain a live execution provider or API credentials. The existing chart/tick engine is a browser-side simulator and cannot be treated as an authoritative live market feed or trade execution service. Real-account trading therefore remains disabled. To enable real-money trades, choose a regulated execution provider and implement its authenticated server-side API integration (order placement, market result callbacks, idempotency, reconciliation, and audit ledger). Never put provider secrets in these HTML files.
