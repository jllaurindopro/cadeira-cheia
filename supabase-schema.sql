-- Cadeira Cheia · estrutura do banco (Supabase / Postgres)
-- Dono e barbeiros entram com login. Clientes agendam pelo link público, sem login,
-- através das funções public_shop / book / client_appts / client_cancel.

-- ============ TABELAS ============
create table if not exists public.shops (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique default auth.uid() references auth.users(id) on delete cascade,
  name text not null default 'Minha barbearia',
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.barbers (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null,
  phone text not null default '',
  com numeric not null default 50,
  email text,
  user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.services (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null,
  price numeric not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.appointments (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  date text not null check (date ~ '^\d{4}-\d{2}-\d{2}$'),
  time text not null check (time ~ '^\d{2}:\d{2}$'),
  barber_id text not null,
  service_id text not null,
  price numeric not null default 0,
  client text not null,
  phone text not null default '',
  status text not null default 'agendado' check (status in ('agendado','atendido','faltou')),
  source text not null default 'recepcao',
  created_at timestamptz not null default now()
);
-- impede dois clientes no mesmo horário com o mesmo barbeiro
create unique index if not exists appointments_no_double
  on public.appointments (shop_id, date, time, barber_id) where status <> 'faltou';
create index if not exists appointments_shop_date on public.appointments (shop_id, date);

create table if not exists public.products (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  name text not null,
  qty integer not null default 0,
  min integer not null default 0,
  price numeric not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.sales (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  date text not null,
  product_id text not null,
  qty integer not null default 1,
  price numeric not null default 0,
  barber_id text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.messages (
  id text primary key,
  shop_id uuid not null references public.shops(id) on delete cascade,
  at timestamptz not null default now(),
  kind text not null default '',
  "to" text not null default '',
  phone text not null default '',
  text text not null default '',
  aud text not null default 'cliente'
);

-- ============ QUEM É QUEM ============
create or replace function public.is_owner(p_shop uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from shops where id = p_shop and owner_id = auth.uid());
$$;

create or replace function public.my_barber_id(p_shop uuid) returns text
language sql stable security definer set search_path = public as $$
  select id from barbers where shop_id = p_shop and user_id = auth.uid() limit 1;
$$;

create or replace function public.is_member(p_shop uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_owner(p_shop) or public.my_barber_id(p_shop) is not null;
$$;

-- Liga a conta do barbeiro ao cadastro feito pelo dono, usando o código de convite
-- que o dono vê em "Equipe e preços" e passa para o barbeiro.
alter table public.barbers add column if not exists invite text;
drop function if exists public.link_me();
create or replace function public.link_code(p_code text) returns text
language plpgsql security definer set search_path = public as $$
declare v_id text;
begin
  if auth.uid() is null or length(coalesce(p_code,'')) < 6 then return null; end if;
  update barbers set user_id = auth.uid(), invite = null
   where user_id is null and invite is not null and upper(invite) = upper(trim(p_code))
  returning id into v_id;
  return v_id;
end $$;

-- ============ REGRAS DE ACESSO (RLS) ============
alter table public.shops enable row level security;
alter table public.barbers enable row level security;
alter table public.services enable row level security;
alter table public.appointments enable row level security;
alter table public.products enable row level security;
alter table public.sales enable row level security;
alter table public.messages enable row level security;

drop policy if exists shops_select on public.shops;
drop policy if exists shops_insert on public.shops;
drop policy if exists shops_update on public.shops;
create policy shops_select on public.shops for select to authenticated using (owner_id = auth.uid() or public.is_member(id));
create policy shops_insert on public.shops for insert to authenticated with check (owner_id = auth.uid());
create policy shops_update on public.shops for update to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- barbeiros e serviços: equipe vê, só o dono altera
drop policy if exists barbers_select on public.barbers;
drop policy if exists barbers_owner on public.barbers;
create policy barbers_select on public.barbers for select to authenticated using (public.is_member(shop_id));
create policy barbers_owner on public.barbers for all to authenticated using (public.is_owner(shop_id)) with check (public.is_owner(shop_id));

drop policy if exists services_select on public.services;
drop policy if exists services_owner on public.services;
create policy services_select on public.services for select to authenticated using (public.is_member(shop_id));
create policy services_owner on public.services for all to authenticated using (public.is_owner(shop_id)) with check (public.is_owner(shop_id));

-- agenda: dono vê tudo; barbeiro só a dele
drop policy if exists appts_owner on public.appointments;
drop policy if exists appts_barber on public.appointments;
create policy appts_owner on public.appointments for all to authenticated
  using (public.is_owner(shop_id)) with check (public.is_owner(shop_id));
create policy appts_barber on public.appointments for all to authenticated
  using (barber_id = public.my_barber_id(shop_id)) with check (barber_id = public.my_barber_id(shop_id));

-- estoque: só o dono
drop policy if exists products_owner on public.products;
create policy products_owner on public.products for all to authenticated using (public.is_owner(shop_id)) with check (public.is_owner(shop_id));

-- vendas: dono tudo; barbeiro lê as dele
drop policy if exists sales_owner on public.sales;
drop policy if exists sales_barber on public.sales;
create policy sales_owner on public.sales for all to authenticated using (public.is_owner(shop_id)) with check (public.is_owner(shop_id));
create policy sales_barber on public.sales for select to authenticated using (barber_id = public.my_barber_id(shop_id));

-- registro de mensagens: equipe registra e lê; só o dono apaga
drop policy if exists msgs_select on public.messages;
drop policy if exists msgs_insert on public.messages;
drop policy if exists msgs_delete on public.messages;
create policy msgs_select on public.messages for select to authenticated using (public.is_member(shop_id));
create policy msgs_insert on public.messages for insert to authenticated with check (public.is_member(shop_id));
create policy msgs_delete on public.messages for delete to authenticated using (public.is_owner(shop_id));

-- ============ LINK PÚBLICO DO CLIENTE (sem login) ============
-- Dados para a tela de agendamento: nada de nomes ou telefones de outros clientes.
create or replace function public.public_shop(p_shop uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'id', s.id,
    'name', s.name,
    'club', coalesce(s.settings -> 'club', '{"every":10,"plan":"Clube","price":99}'::jsonb),
    'ownerPhone', coalesce(s.settings #>> '{owner,phone}', ''),
    'barbers', coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'name', b.name) order by b.created_at)
                          from barbers b where b.shop_id = s.id), '[]'::jsonb),
    'services', coalesce((select jsonb_agg(jsonb_build_object('id', v.id, 'name', v.name, 'price', v.price) order by v.created_at)
                          from services v where v.shop_id = s.id), '[]'::jsonb),
    'busy', coalesce((select jsonb_agg(jsonb_build_object('date', a.date, 'time', a.time, 'barberId', a.barber_id))
                          from appointments a
                         where a.shop_id = s.id and a.status <> 'faltou'
                           and a.date >= to_char((now() at time zone 'America/Sao_Paulo')::date, 'YYYY-MM-DD')
                           and a.date <= to_char((now() at time zone 'America/Sao_Paulo')::date + 15, 'YYYY-MM-DD')), '[]'::jsonb)
  ) from shops s where s.id = p_shop;
$$;

-- Cliente marca horário. Valida serviço, barbeiro, data, conflito e dados.
create or replace function public.book(p_shop uuid, p_date text, p_time text, p_barber text, p_service text,
                                       p_client text, p_phone text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_today date := (now() at time zone 'America/Sao_Paulo')::date;
  v_price numeric; v_barber text := p_barber; v_id text;
begin
  if p_date !~ '^\d{4}-\d{2}-\d{2}$' or p_time !~ '^\d{2}:\d{2}$' then raise exception 'data_invalida'; end if;
  if p_date::date < v_today or p_date::date > v_today + 15 then raise exception 'data_invalida'; end if;
  if length(trim(coalesce(p_client,''))) < 2 or length(p_client) > 60 then raise exception 'nome_invalido'; end if;
  if length(regexp_replace(coalesce(p_phone,''), '\D', '', 'g')) < 10 or length(p_phone) > 25 then raise exception 'telefone_invalido'; end if;
  select price into v_price from services where id = p_service and shop_id = p_shop;
  if v_price is null then raise exception 'servico_invalido'; end if;
  -- limite simples contra abuso: no máximo 3 horários futuros por telefone
  if (select count(*) from appointments where shop_id = p_shop and status = 'agendado' and date >= to_char(v_today,'YYYY-MM-DD')
        and regexp_replace(phone,'\D','','g') = regexp_replace(p_phone,'\D','','g')) >= 3 then
    raise exception 'limite_horarios';
  end if;
  if v_barber = 'any' then
    select b.id into v_barber from barbers b
     where b.shop_id = p_shop and not exists (
       select 1 from appointments a where a.shop_id = p_shop and a.date = p_date and a.time = p_time
          and a.barber_id = b.id and a.status <> 'faltou')
     order by random() limit 1;
    if v_barber is null then raise exception 'horario_ocupado'; end if;
  elsif not exists (select 1 from barbers where id = v_barber and shop_id = p_shop) then
    raise exception 'barbeiro_invalido';
  end if;
  v_id := substr(md5(random()::text || clock_timestamp()::text), 1, 10);
  begin
    insert into appointments (id, shop_id, date, time, barber_id, service_id, price, client, phone, status, source)
    values (v_id, p_shop, p_date, p_time, v_barber, p_service, v_price, trim(p_client), trim(p_phone), 'agendado', 'link');
  exception when unique_violation then raise exception 'horario_ocupado';
  end;
  return jsonb_build_object('id', v_id, 'barberId', v_barber, 'price', v_price);
end $$;

-- Horários do próprio cliente: precisa do código do agendamento E do telefone usado nele.
create or replace function public.client_appts(p_shop uuid, p_ids text[], p_phone text) returns jsonb
language sql stable security definer set search_path = public as $$
  with digits as (select regexp_replace(coalesce(p_phone,''),'\D','','g') d)
  select jsonb_build_object(
    'appts', coalesce((select jsonb_agg(jsonb_build_object('id',a.id,'date',a.date,'time',a.time,'barberId',a.barber_id,
                                 'serviceId',a.service_id,'price',a.price,'status',a.status))
                         from appointments a, digits
                        where a.shop_id = p_shop and a.id = any(p_ids)
                          and regexp_replace(a.phone,'\D','','g') = digits.d and length(digits.d) >= 10), '[]'::jsonb),
    'visits', (select count(*) from appointments a, digits
                where a.shop_id = p_shop and a.status = 'atendido' and length(digits.d) >= 10
                  and regexp_replace(a.phone,'\D','','g') = digits.d
                  and exists (select 1 from appointments x where x.shop_id = p_shop and x.id = any(p_ids)
                                and regexp_replace(x.phone,'\D','','g') = digits.d))
  );
$$;

create or replace function public.client_cancel(p_shop uuid, p_id text, p_phone text) returns boolean
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  delete from appointments
   where shop_id = p_shop and id = p_id and status = 'agendado'
     and date >= to_char((now() at time zone 'America/Sao_Paulo')::date,'YYYY-MM-DD')
     and regexp_replace(phone,'\D','','g') = regexp_replace(coalesce(p_phone,''),'\D','','g');
  get diagnostics n = row_count;
  return n > 0;
end $$;

-- Permissões das funções
revoke all on function public.public_shop(uuid) from public;
revoke all on function public.book(uuid,text,text,text,text,text,text) from public;
revoke all on function public.client_appts(uuid,text[],text) from public;
revoke all on function public.client_cancel(uuid,text,text) from public;
revoke all on function public.link_code(text) from public;
grant execute on function public.public_shop(uuid) to anon, authenticated;
grant execute on function public.book(uuid,text,text,text,text,text,text) to anon, authenticated;
grant execute on function public.client_appts(uuid,text[],text) to anon, authenticated;
grant execute on function public.client_cancel(uuid,text,text) to anon, authenticated;
grant execute on function public.link_code(text) to authenticated;
revoke all on function public.is_owner(uuid) from public;
revoke all on function public.my_barber_id(uuid) from public;
revoke all on function public.is_member(uuid) from public;
grant execute on function public.is_owner(uuid) to authenticated;
grant execute on function public.my_barber_id(uuid) to authenticated;
grant execute on function public.is_member(uuid) to authenticated;

-- Atualização em tempo real para a equipe
do $$ begin
  begin alter publication supabase_realtime add table public.appointments; exception when others then null; end;
  begin alter publication supabase_realtime add table public.barbers; exception when others then null; end;
  begin alter publication supabase_realtime add table public.services; exception when others then null; end;
  begin alter publication supabase_realtime add table public.sales; exception when others then null; end;
  begin alter publication supabase_realtime add table public.products; exception when others then null; end;
  begin alter publication supabase_realtime add table public.shops; exception when others then null; end;
end $$;
