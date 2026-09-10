const STAGING_UPSERT_SIZE = Math.min(
  2500,
  Math.max(200, Number(process.env.BULK_UPSERT_CHUNK_SIZE) || 1000),
);
const MAX_RECORDS_PER_CHUNK = 8000;

function asText(value) {
  if (value == null) return null;
  if (Array.isArray(value)) {
    const joined = value.map((item) => String(item || '').trim()).filter(Boolean).join(' ');
    return joined || null;
  }
  const text = String(value).trim();
  return text || null;
}

function normalizeWatchlistRow(row) {
  const plate = asText(
    row?.plate_number
    || row?.key
    || row?.normalizedPlate
    || row?.display
    || row?.plate
    || row?.لوحة,
  );
  if (!plate) return null;
  return {
    plate_number: plate,
    letters: asText(row.letters || row.الحروف),
    numbers: asText(row.numbers != null ? row.numbers : row.الأرقام),
    vehicle_type: asText(row.vehicle_type || row.vehicleType || row.النوع),
    vin: asText(row.vin || row.vinLast4 || row.الشاص || row.الهيكل),
    notes: asText(row.notes || row.سبب || row.reason),
  };
}

function importIdentity(body) {
  return String(body?.import_id || body?.upload_id || '').trim();
}

function clientSafeMessage(err, fallback) {
  const raw = String(err?.message || fallback || 'Watchlist import failed.');
  if (/service_role|JWT|SUPABASE|password|stack|schema cache|PGRST/i.test(raw)) {
    return fallback || 'Watchlist import failed.';
  }
  return raw.replace(/^IMPORT_[A-Z_]+:\s*/i, '').slice(0, 300);
}

function mapWatchlistError(err) {
  const raw = String(err?.message || '');
  const status = Number(err.status) || 500;
  if (err.code && status < 500 && status >= 400) {
    return {
      status,
      code: err.code,
      message: clientSafeMessage(err, err.message),
    };
  }
  if (/IMPORT_NOT_FOUND/i.test(raw)) {
    return { status: 404, code: 'IMPORT_NOT_FOUND', message: clientSafeMessage(err, 'Import session was not found.') };
  }
  if (/IMPORT_EMPTY/i.test(raw)) {
    return { status: 422, code: 'IMPORT_EMPTY', message: clientSafeMessage(err, 'Empty watchlist datasets cannot replace the active list.') };
  }
  if (/IMPORT_INCOMPLETE/i.test(raw)) {
    return { status: 422, code: 'IMPORT_INCOMPLETE', message: clientSafeMessage(err, 'Import is incomplete; the current watchlist was not replaced.') };
  }
  if (/IMPORT_CONFLICT/i.test(raw) || /duplicate key|23505/i.test(raw)) {
    return { status: 409, code: 'IMPORT_CONFLICT', message: clientSafeMessage(err, 'This import conflicts with an existing session.') };
  }
  if (/IMPORT_FORBIDDEN/i.test(raw)) {
    return { status: 403, code: 'WATCHLIST_FORBIDDEN', message: clientSafeMessage(err, 'This device is not allowed to import a watchlist.') };
  }
  return {
    status: status >= 400 ? status : 500,
    code: err.code || 'WATCHLIST_IMPORT_FAILED',
    message: status >= 500
      ? 'Watchlist import failed.'
      : clientSafeMessage(err, 'Watchlist import failed.'),
  };
}

async function bulkUpsert(supabase, table, rows, onConflict) {
  if (!rows.length) return;
  for (let offset = 0; offset < rows.length; offset += STAGING_UPSERT_SIZE) {
    const chunk = rows.slice(offset, offset + STAGING_UPSERT_SIZE);
    const { error } = await supabase.from(table).upsert(chunk, { onConflict });
    if (error) {
      const wrapped = new Error(error.message);
      wrapped.code = 'UPSERT_FAILED';
      wrapped.status = 500;
      throw wrapped;
    }
  }
}

async function loadImport(supabase, importId) {
  const { data, error } = await supabase
    .from('watchlist_imports')
    .select('*')
    .eq('id', importId)
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

async function refreshReceivedCounts(supabase, importId) {
  const [{ count: chunkCount, error: chunkError }, { count: rowCount, error: rowError }] = await Promise.all([
    supabase
      .from('watchlist_import_chunks')
      .select('chunk_index', { count: 'exact', head: true })
      .eq('import_id', importId),
    supabase
      .from('watchlist_import_rows')
      .select('row_index', { count: 'exact', head: true })
      .eq('import_id', importId),
  ]);
  if (chunkError) throw chunkError;
  if (rowError) throw rowError;
  const received_chunks = Number(chunkCount || 0);
  const received_records = Number(rowCount || 0);
  const { error } = await supabase
    .from('watchlist_imports')
    .update({
      received_chunks,
      received_records,
      updated_at: new Date().toISOString(),
    })
    .eq('id', importId)
    .in('status', ['receiving', 'ready']);
  if (error) throw error;
  return { received_chunks, received_records };
}

function importIsComplete(session, received) {
  return Number(session.expected_chunks) > 0
    && Number(session.expected_records) > 0
    && received.received_chunks === Number(session.expected_chunks)
    && received.received_records === Number(session.expected_records);
}

async function initializeImport(supabase, { body, license, importId }) {
  const datasetId = String(body.dataset_id || body.dataset?.id || '').trim();
  if (!datasetId) {
    const error = new Error('dataset_id is required.');
    error.status = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  const expectedRecords = Math.max(0, Number(body.total_records ?? body.expected_records) || 0);
  const expectedChunks = Math.max(1, Number(body.total_chunks ?? body.expected_chunks) || 1);
  const chunkSize = Math.max(1, Number(body.chunk_size) || 3000);
  const deviceId = String(body.device_id || '').trim();
  const existing = await loadImport(supabase, importId);

  if (existing && existing.device_id !== deviceId) {
    const error = new Error('This import belongs to another device.');
    error.status = 403;
    error.code = 'WATCHLIST_FORBIDDEN';
    throw error;
  }

  if (existing && existing.status === 'active'
      && existing.dataset_id === datasetId
      && Number(existing.expected_records) === expectedRecords
      && Number(existing.expected_chunks) === expectedChunks) {
    return {
      ok: true,
      import_id: importId,
      upload_id: importId,
      status: 'active',
      rows: Number(existing.received_records) || 0,
      code: 'IMPORTED',
    };
  }

  if (
    existing
    && existing.status === 'receiving'
    && existing.dataset_id === datasetId
    && Number(existing.expected_records) === expectedRecords
    && Number(existing.expected_chunks) === expectedChunks
    && Number(existing.chunk_size) === chunkSize
  ) {
    return {
      ok: true,
      import_id: importId,
      upload_id: importId,
      status: existing.status,
      rows: Number(existing.received_records) || 0,
    };
  }

  if (existing && existing.status === 'activating') {
    const error = new Error('This import is already being activated.');
    error.status = 409;
    error.code = 'IMPORT_CONFLICT';
    throw error;
  }

  if (existing && ['receiving', 'ready', 'failed', 'active', 'superseded'].includes(existing.status)) {
    const { error: rowDeleteError } = await supabase
      .from('watchlist_import_rows')
      .delete()
      .eq('import_id', importId);
    if (rowDeleteError) throw rowDeleteError;
    const { error: chunkDeleteError } = await supabase
      .from('watchlist_import_chunks')
      .delete()
      .eq('import_id', importId);
    if (chunkDeleteError) throw chunkDeleteError;
  }

  const session = {
    id: importId,
    dataset_id: datasetId,
    device_id: deviceId,
    license_id: license.id || null,
    license_code: license.code || String(body.activation_code || '').trim() || null,
    expected_records: expectedRecords,
    expected_chunks: expectedChunks,
    chunk_size: chunkSize,
    received_records: 0,
    received_chunks: 0,
    status: 'receiving',
    error_message: null,
    updated_at: new Date().toISOString(),
    completed_at: null,
    activated_at: null,
  };
  const { error } = await supabase
    .from('watchlist_imports')
    .upsert(session, { onConflict: 'id' });
  if (error) throw error;
  return {
    ok: true,
    import_id: importId,
    upload_id: importId,
    status: 'receiving',
    rows: 0,
  };
}

async function activateImport(supabase, { importId, license, deviceId }) {
  const { data, error } = await supabase.rpc('activate_watchlist_import', {
    p_import_id: importId,
    p_imported_by: license.bound_user_email || license.code || deviceId,
  });
  if (error) throw error;
  const payload = data && typeof data === 'object' ? data : {};
  return {
    ok: true,
    import_id: importId,
    upload_id: importId,
    status: payload.status || 'active',
    rows: Number(payload.rows) || 0,
    code: 'IMPORTED',
  };
}

async function stageChunk(supabase, { body, license, importId }) {
  const chunkIndex = Number(body.chunk_index);
  const records = Array.isArray(body.records) ? body.records : (Array.isArray(body.entries) ? body.entries : []);
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0) {
    const error = new Error('A valid chunk_index is required.');
    error.status = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  if (records.length > MAX_RECORDS_PER_CHUNK) {
    const error = new Error(`A chunk cannot contain more than ${MAX_RECORDS_PER_CHUNK} rows.`);
    error.status = 413;
    error.code = 'PAYLOAD_TOO_LARGE';
    throw error;
  }

  const session = await loadImport(supabase, importId);
  if (!session) {
    const error = new Error('Import session was not found. Initialize the import first.');
    error.status = 404;
    error.code = 'IMPORT_NOT_FOUND';
    throw error;
  }
  const deviceId = String(body.device_id || '').trim();
  if (session.device_id !== deviceId) {
    const error = new Error('This import belongs to another device.');
    error.status = 403;
    error.code = 'WATCHLIST_FORBIDDEN';
    throw error;
  }
  if (session.status === 'active') {
    return {
      ok: true,
      import_id: importId,
      upload_id: importId,
      status: 'active',
      rows: Number(session.received_records) || 0,
      code: 'IMPORTED',
    };
  }
  if (session.status !== 'receiving' && session.status !== 'ready') {
    const error = new Error(`Import ${importId} cannot accept chunks in status ${session.status}.`);
    error.status = 409;
    error.code = 'IMPORT_CONFLICT';
    throw error;
  }
  if (chunkIndex >= Number(session.expected_chunks)) {
    const error = new Error('chunk_index is outside the declared import range.');
    error.status = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  const declaredChunkSize = Number(body.chunk_size);
  if (Number.isFinite(declaredChunkSize) && declaredChunkSize > 0 && declaredChunkSize !== Number(session.chunk_size)) {
    const error = new Error('chunk_size does not match the initialized import.');
    error.status = 409;
    error.code = 'IMPORT_CONFLICT';
    throw error;
  }

  const chunkSize = Number(session.chunk_size) || 3000;
  const normalized = records
    .map(normalizeWatchlistRow)
    .filter(Boolean)
    .map((row, rowIndex) => ({
      import_id: importId,
      row_index: chunkIndex * chunkSize + rowIndex,
      chunk_index: chunkIndex,
      ...row,
    }));

  await bulkUpsert(supabase, 'watchlist_import_rows', normalized, 'import_id,row_index');
  const { error: chunkError } = await supabase
    .from('watchlist_import_chunks')
    .upsert({
      import_id: importId,
      chunk_index: chunkIndex,
      row_count: normalized.length,
      received_at: new Date().toISOString(),
    }, { onConflict: 'import_id,chunk_index' });
  if (chunkError) throw chunkError;

  const received = await refreshReceivedCounts(supabase, importId);
  const complete = importIsComplete(session, received);
  if (complete) {
    return activateImport(supabase, { importId, license, deviceId });
  }

  if (body.is_last === true) {
    const error = new Error(
      `IMPORT_INCOMPLETE: expected ${session.expected_chunks} chunks / ${session.expected_records} rows, received ${received.received_chunks} / ${received.received_records}`,
    );
    error.status = 422;
    error.code = 'IMPORT_INCOMPLETE';
    throw error;
  }

  return {
    ok: true,
    import_id: importId,
    upload_id: importId,
    status: 'receiving',
    chunk_index: chunkIndex,
    accepted: normalized.length,
    rows: received.received_records,
  };
}

async function handleWatchlistImportChunk(req, supabase, authorizeWatchlistDevice) {
  const body = req.body || {};
  const license = await authorizeWatchlistDevice(body);
  const importId = importIdentity(body);
  if (!importId) {
    const error = new Error('import_id or upload_id is required.');
    error.status = 400;
    error.code = 'BAD_REQUEST';
    throw error;
  }
  if (body.action === 'initialize') {
    return initializeImport(supabase, { body, license, importId });
  }
  return stageChunk(supabase, { body, license, importId });
}

module.exports = {
  handleWatchlistImportChunk,
  mapWatchlistError,
  normalizeWatchlistRow,
};
