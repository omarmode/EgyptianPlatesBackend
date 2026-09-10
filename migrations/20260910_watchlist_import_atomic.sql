-- Additive watchlist import staging + atomic activation.
-- Live project currently has public.watchlist_plates only.
-- This migration does not DROP that table or delete existing plate rows.

create table if not exists public.watchlist_imports (
  id text primary key,
  dataset_id text not null,
  device_id text not null,
  license_id uuid,
  license_code text,
  expected_records integer not null default 0,
  expected_chunks integer not null default 1,
  chunk_size integer not null default 3000,
  received_records integer not null default 0,
  received_chunks integer not null default 0,
  status text not null default 'receiving',
  error_message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz,
  activated_at timestamptz
);

alter table public.watchlist_imports add column if not exists license_id uuid;
alter table public.watchlist_imports add column if not exists license_code text;
alter table public.watchlist_imports add column if not exists chunk_size integer;
alter table public.watchlist_imports add column if not exists received_records integer;
alter table public.watchlist_imports add column if not exists received_chunks integer;
alter table public.watchlist_imports add column if not exists error_message text;
alter table public.watchlist_imports add column if not exists completed_at timestamptz;
alter table public.watchlist_imports add column if not exists activated_at timestamptz;

update public.watchlist_imports set chunk_size = 3000 where chunk_size is null;
update public.watchlist_imports set received_records = 0 where received_records is null;
update public.watchlist_imports set received_chunks = 0 where received_chunks is null;
alter table public.watchlist_imports alter column chunk_size set default 3000;
alter table public.watchlist_imports alter column received_records set default 0;
alter table public.watchlist_imports alter column received_chunks set default 0;
alter table public.watchlist_imports alter column chunk_size set not null;
alter table public.watchlist_imports alter column received_records set not null;
alter table public.watchlist_imports alter column received_chunks set not null;

alter table public.watchlist_imports drop constraint if exists watchlist_imports_expected_records_check;
alter table public.watchlist_imports add constraint watchlist_imports_expected_records_check
  check (expected_records >= 0);
alter table public.watchlist_imports drop constraint if exists watchlist_imports_expected_chunks_check;
alter table public.watchlist_imports add constraint watchlist_imports_expected_chunks_check
  check (expected_chunks >= 1);
alter table public.watchlist_imports drop constraint if exists watchlist_imports_chunk_size_check;
alter table public.watchlist_imports add constraint watchlist_imports_chunk_size_check
  check (chunk_size >= 1);
alter table public.watchlist_imports drop constraint if exists watchlist_imports_status_check;
alter table public.watchlist_imports add constraint watchlist_imports_status_check
  check (status in ('receiving', 'ready', 'activating', 'active', 'failed', 'superseded'));

create table if not exists public.watchlist_import_rows (
  import_id text not null references public.watchlist_imports(id) on delete cascade,
  row_index integer not null,
  chunk_index integer not null default 0,
  plate_number text not null,
  letters text,
  numbers text,
  vehicle_type text,
  vin text,
  notes text,
  primary key (import_id, row_index)
);

alter table public.watchlist_import_rows add column if not exists chunk_index integer;
update public.watchlist_import_rows set chunk_index = 0 where chunk_index is null;
alter table public.watchlist_import_rows alter column chunk_index set default 0;
alter table public.watchlist_import_rows alter column chunk_index set not null;
alter table public.watchlist_import_rows drop constraint if exists watchlist_import_rows_row_index_check;
alter table public.watchlist_import_rows add constraint watchlist_import_rows_row_index_check
  check (row_index >= 0);
alter table public.watchlist_import_rows drop constraint if exists watchlist_import_rows_chunk_index_check;
alter table public.watchlist_import_rows add constraint watchlist_import_rows_chunk_index_check
  check (chunk_index >= 0);

create table if not exists public.watchlist_import_chunks (
  import_id text not null references public.watchlist_imports(id) on delete cascade,
  chunk_index integer not null,
  row_count integer not null default 0,
  received_at timestamptz not null default now(),
  primary key (import_id, chunk_index)
);

alter table public.watchlist_import_chunks drop constraint if exists watchlist_import_chunks_chunk_index_check;
alter table public.watchlist_import_chunks add constraint watchlist_import_chunks_chunk_index_check
  check (chunk_index >= 0);
alter table public.watchlist_import_chunks drop constraint if exists watchlist_import_chunks_row_count_check;
alter table public.watchlist_import_chunks add constraint watchlist_import_chunks_row_count_check
  check (row_count >= 0);

alter table public.watchlist_plates add column if not exists dataset_id text;
alter table public.watchlist_plates add column if not exists import_id text;

create index if not exists watchlist_imports_device_status_idx
  on public.watchlist_imports (device_id, status);
create index if not exists watchlist_imports_status_updated_idx
  on public.watchlist_imports (status, updated_at desc);
create index if not exists watchlist_imports_license_idx
  on public.watchlist_imports (license_id);
create index if not exists watchlist_import_rows_import_idx
  on public.watchlist_import_rows (import_id, row_index);
create index if not exists watchlist_import_rows_plate_idx
  on public.watchlist_import_rows (import_id, plate_number);
create index if not exists watchlist_import_chunks_import_idx
  on public.watchlist_import_chunks (import_id, chunk_index);
create index if not exists watchlist_plates_import_idx
  on public.watchlist_plates (import_id);
create index if not exists watchlist_plates_dataset_idx
  on public.watchlist_plates (dataset_id);
create index if not exists watchlist_plates_updated_at_idx
  on public.watchlist_plates (updated_at desc);

alter table public.watchlist_imports enable row level security;
alter table public.watchlist_import_rows enable row level security;
alter table public.watchlist_import_chunks enable row level security;
alter table public.watchlist_plates enable row level security;

revoke all on table public.watchlist_imports from public, anon, authenticated;
revoke all on table public.watchlist_import_rows from public, anon, authenticated;
revoke all on table public.watchlist_import_chunks from public, anon, authenticated;
revoke all on table public.watchlist_plates from public, anon, authenticated;
grant all on table public.watchlist_imports to postgres, service_role;
grant all on table public.watchlist_import_rows to postgres, service_role;
grant all on table public.watchlist_import_chunks to postgres, service_role;
grant all on table public.watchlist_plates to postgres, service_role;

create or replace function public.activate_watchlist_import(
  p_import_id text,
  p_imported_by text default null
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  import_row public.watchlist_imports%rowtype;
  chunk_count integer;
  row_count integer;
  missing_chunks integer;
  active_count integer;
begin
  if p_import_id is null or length(trim(p_import_id)) = 0 then
    raise exception 'IMPORT_NOT_FOUND: import_id is required';
  end if;

  perform pg_advisory_xact_lock(87236401);

  select * into import_row
    from public.watchlist_imports
   where id = p_import_id
   for update;
  if not found then
    raise exception 'IMPORT_NOT_FOUND: unknown import %', p_import_id;
  end if;

  if import_row.status = 'active' then
    select count(*) into active_count
      from public.watchlist_plates
     where import_id = p_import_id;
    if active_count = 0 then
      select count(*) into active_count from public.watchlist_plates;
    end if;
    return jsonb_build_object(
      'ok', true,
      'status', 'active',
      'import_id', p_import_id,
      'rows', active_count,
      'idempotent', true
    );
  end if;

  if import_row.status not in ('receiving', 'ready', 'activating') then
    raise exception 'IMPORT_CONFLICT: import % has status %', p_import_id, import_row.status;
  end if;

  if import_row.expected_records <= 0 then
    raise exception 'IMPORT_EMPTY: refusing to replace the active watchlist with an empty dataset';
  end if;

  select count(*) into chunk_count
    from public.watchlist_import_chunks
   where import_id = p_import_id;

  select count(*) into missing_chunks
    from generate_series(0, import_row.expected_chunks - 1) as expected(chunk_index)
    left join public.watchlist_import_chunks c
      on c.import_id = p_import_id and c.chunk_index = expected.chunk_index
   where c.chunk_index is null;

  select count(*) into row_count
    from public.watchlist_import_rows
   where import_id = p_import_id;

  if chunk_count <> import_row.expected_chunks or missing_chunks > 0 then
    raise exception 'IMPORT_INCOMPLETE: expected % chunks, received %',
      import_row.expected_chunks, chunk_count;
  end if;

  if row_count <> import_row.expected_records then
    raise exception 'IMPORT_INCOMPLETE: expected % rows, received %',
      import_row.expected_records, row_count;
  end if;

  update public.watchlist_imports
     set status = 'activating',
         received_chunks = chunk_count,
         received_records = row_count,
         updated_at = now()
   where id = p_import_id;

  insert into public.watchlist_plates (
    plate_number, letters, numbers, vehicle_type, vin, notes,
    imported_by, updated_at, dataset_id, import_id
  )
  select distinct on (plate_number)
    plate_number,
    letters,
    numbers,
    vehicle_type,
    vin,
    notes,
    coalesce(p_imported_by, import_row.license_code, import_row.device_id),
    now(),
    import_row.dataset_id,
    p_import_id
    from public.watchlist_import_rows
   where import_id = p_import_id
   order by plate_number, row_index desc
  on conflict (plate_number) do update
    set letters = excluded.letters,
        numbers = excluded.numbers,
        vehicle_type = excluded.vehicle_type,
        vin = excluded.vin,
        notes = excluded.notes,
        imported_by = excluded.imported_by,
        updated_at = excluded.updated_at,
        dataset_id = excluded.dataset_id,
        import_id = excluded.import_id;

  delete from public.watchlist_plates
   where import_id is distinct from p_import_id;

  update public.watchlist_imports
     set status = 'superseded',
         updated_at = now(),
         completed_at = coalesce(completed_at, now())
   where status = 'active'
     and id <> p_import_id;

  update public.watchlist_imports
     set status = 'active',
         received_chunks = chunk_count,
         received_records = row_count,
         error_message = null,
         updated_at = now(),
         completed_at = now(),
         activated_at = now()
   where id = p_import_id;

  select count(*) into active_count
    from public.watchlist_plates
   where import_id = p_import_id;

  return jsonb_build_object(
    'ok', true,
    'status', 'active',
    'import_id', p_import_id,
    'rows', active_count,
    'idempotent', false
  );
end;
$$;

create or replace function public.cleanup_watchlist_import_staging(
  p_older_than interval default interval '7 days'
) returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  removed integer;
begin
  delete from public.watchlist_imports
   where status in ('failed', 'superseded')
     and updated_at < now() - p_older_than;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function public.activate_watchlist_import(text, text) from public, anon, authenticated;
revoke all on function public.cleanup_watchlist_import_staging(interval) from public, anon, authenticated;
grant execute on function public.activate_watchlist_import(text, text) to postgres, service_role;
grant execute on function public.cleanup_watchlist_import_staging(interval) to postgres, service_role;

comment on table public.watchlist_imports is
  'One import session per upload_id. Staging only; never the live watchlist.';
comment on table public.watchlist_import_rows is
  'Normalized watchlist rows staged by import_id until atomic activation.';
comment on table public.watchlist_import_chunks is
  'Chunk receipts used to prove completeness before activation.';
comment on function public.activate_watchlist_import(text, text) is
  'Atomically replace watchlist_plates only after every expected chunk and row has arrived.';

notify pgrst, 'reload schema';
