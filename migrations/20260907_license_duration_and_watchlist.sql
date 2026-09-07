alter table public.licenses
  add column if not exists duration_hours integer,
  add column if not exists duration_months integer,
  add column if not exists duration_unit text;

comment on column public.licenses.duration_hours is 'Optional hour-based validity; applied from first use unless duration_unit=custom.';
comment on column public.licenses.duration_months is 'Optional month-based validity; applied from first use.';
comment on column public.licenses.duration_unit is 'hours | days | months | custom';

create table if not exists public.watchlist_plates (
  plate_number text primary key,
  letters text,
  numbers text,
  vehicle_type text,
  vin text,
  notes text,
  imported_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.watchlist_plates enable row level security;

create index if not exists watchlist_plates_updated_at_idx
  on public.watchlist_plates (updated_at desc);
