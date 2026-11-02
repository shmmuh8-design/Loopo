-- لوبو: تحديث 2 — تأكيد رقم الهاتف برمز SMS (OTP) عند التسجيل، واسترجاع الحساب على جوال جديد
-- قبل ما تشغّله: فعّل Phone في Supabase → Authentication → Sign In / Providers (Twilio).
-- انسخ الملف كامل والصقه في SQL Editor (مشروع سُقيا) واضغط Run.

-- الرقم المؤكَّد من رمز الـ SMS (من توكن Supabase Auth)، بدون + ومسافات
create or replace function public._hb_otp_phone() returns text
language sql stable set search_path = public as $$
  select nullif(regexp_replace(coalesce(auth.jwt() ->> 'phone', ''), '\D', '', 'g'), '')
$$;

-- التسجيل: لازم رقم مؤكَّد برمز SMS
drop function if exists public.hb_register(text, text, text, text, text);
create function public.hb_register(p_username text, p_phone text, p_email text, p_name text, p_pubkey text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_secret text := encode(gen_random_bytes(24), 'hex'); v_id uuid;
  v_user text := nullif(lower(trim(coalesce(p_username, ''))), '');
  v_phone text := nullif(regexp_replace(coalesce(p_phone, ''), '\D', '', 'g'), '');
  v_mail text := nullif(lower(trim(coalesce(p_email, ''))), '');
  v_ok text := _hb_otp_phone();
begin
  if length(v_phone) = 8 then v_phone := '968' || v_phone; end if;
  if v_phone is null then raise exception 'اكتب رقم هاتفك عشان نرسل لك رمز التأكيد'; end if;
  if v_ok is null or v_ok <> v_phone then raise exception 'لازم تأكد رقمك برمز الرسالة أول'; end if;
  if v_user is not null and exists (select 1 from hb_users where username = v_user) then raise exception 'اسم المستخدم مأخوذ، جرّب غيره'; end if;
  if exists (select 1 from hb_users where phone = v_phone) then raise exception 'هذا الرقم مسجّل في لوبو من قبل — اضغط «عندي حساب»'; end if;
  if v_mail is not null and exists (select 1 from hb_users where email = v_mail) then raise exception 'هذا الإيميل مسجّل في لوبو من قبل'; end if;
  if (select count(*) from hb_users where created_at > now() - interval '1 hour') > 100 then raise exception 'ضغط تسجيلات كثير، حاول بعد شوي'; end if;
  insert into hb_users(username, phone, phone_ok, email, name, pubkey, secret_hash)
  values (v_user, v_phone, true, v_mail, nullif(trim(coalesce(p_name, '')), ''), p_pubkey, crypt(v_secret, gen_salt('bf')))
  returning id into v_id;
  return json_build_object('id', v_id, 'secret', v_secret);
end $$;

-- عندي حساب (جوال جديد أو حذفت التطبيق): برمز SMS ترجع لحسابك بمفتاح تشفير جديد.
-- الرسائل القديمة ما تنفتح (لأنها مشفّرة بالمفتاح القديم) وتنمسح.
create or replace function public.hb_recover(p_pubkey text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_ok text := _hb_otp_phone(); u hb_users; v_secret text := encode(gen_random_bytes(24), 'hex');
begin
  if v_ok is null then raise exception 'لازم تأكد رقمك برمز الرسالة أول'; end if;
  select * into u from hb_users where phone = v_ok;
  if u.id is null then raise exception 'ما فيه حساب لوبو بهالرقم — سجّل حساب جديد'; end if;
  if u.status = 'blocked' then raise exception 'حسابك موقوف بسبب بلاغات'; end if;
  delete from hb_msgs where from_id = u.id or to_id = u.id;
  update hb_users set pubkey = p_pubkey, secret_hash = crypt(v_secret, gen_salt('bf')), phone_ok = true, last_seen = now() where id = u.id;
  return json_build_object('id', u.id, 'secret', v_secret);
end $$;

grant execute on function public._hb_otp_phone() to anon, authenticated;
grant execute on function public.hb_register(text, text, text, text, text), public.hb_recover(text) to anon, authenticated;
