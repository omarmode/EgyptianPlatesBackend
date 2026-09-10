const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');
const importLib = fs.readFileSync(path.join(root, 'lib', 'watchlistImport.js'), 'utf8');
const migration = fs.readFileSync(
  path.join(root, 'migrations', '20260910_watchlist_import_atomic.sql'),
  'utf8',
);
const frontendRoot = path.resolve(root, '..', 'EgyptianPlatesApp');
const upload = fs.readFileSync(path.join(frontendRoot, 'services', 'watchlistUploadService.js'), 'utf8');
const config = fs.readFileSync(path.join(frontendRoot, 'src', 'admin', 'config.js'), 'utf8');

assert.match(server, /app\.post\('\/api\/watchlist\/import\/chunk'/);
assert.match(server, /authorizeWatchlistDevice/);
assert.match(server, /activation_code and device_id are required/);
assert.match(server, /LEGACY admin path/);
assert.match(importLib, /from\('watchlist_import_rows'\)/);
assert.match(importLib, /from\('watchlist_import_chunks'\)/);
assert.match(importLib, /rpc\('activate_watchlist_import'/);
assert.match(importLib, /body\.import_id \|\| body\.upload_id/);
assert.match(migration, /create table if not exists public\.watchlist_imports/);
assert.match(migration, /create table if not exists public\.watchlist_import_rows/);
assert.match(migration, /create table if not exists public\.watchlist_import_chunks/);
assert.match(migration, /create or replace function public\.activate_watchlist_import/);
assert.match(migration, /for update/);
assert.match(migration, /pg_advisory_xact_lock/);
assert.match(migration, /on conflict \(plate_number\) do update/);
assert.match(migration, /revoke all on function public\.activate_watchlist_import/);
assert.doesNotMatch(migration, /delete from public\.watchlist_imports where id <> p_import_id/);
assert.match(upload, /WATCHLIST_UPLOAD_PATH/);
assert.match(upload, /activation_code:/);
assert.match(upload, /device_id:/);
assert.match(upload, /chunk_size:\s*boundedChunkSize/);
assert.match(config, /\/api\/watchlist\/import\/chunk/);
