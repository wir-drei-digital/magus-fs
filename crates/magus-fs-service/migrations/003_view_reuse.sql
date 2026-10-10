-- Additive and repeatable. Legacy IDs/requests/receipts remain intact; NULL
-- authority snapshots are deliberately ineligible for reuse (no guessed backfill).
ALTER TABLE views ADD COLUMN IF NOT EXISTS credential_generation bigint;
ALTER TABLE views ADD COLUMN IF NOT EXISTS grant_actions text[];
ALTER TABLE views ADD COLUMN IF NOT EXISTS grant_branches text[];
ALTER TABLE views ADD COLUMN IF NOT EXISTS grant_prefixes text[];
-- Keep potentially large descriptor/grant values out of B-tree keys. Exact
-- authority/content equality is checked after this bounded identity lookup.
CREATE INDEX IF NOT EXISTS views_reuse_lookup
ON views(namespace,branch,credential,full_revision,head,projected_revision);
