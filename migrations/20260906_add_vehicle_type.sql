alter table public.detected_locations
  add column if not exists vehicle_type text;

comment on column public.detected_locations.vehicle_type is
  'Optional spoken vehicle type; never part of plate_number.';
