-- FS2-B Task 2 collaboration records. Additive and repeatable; only the R21 identity registry
-- is backfilled, from immutable published revisions (facts, no fabricated provenance).
-- Candidates committed before this migration have no causality sidecar and are judged by
-- their derived descriptor provenance only. Conflict payloads are immutable (payload+digest);
-- resolution is a separate link row, so a resolved conflict keeps its original alternatives.
CREATE TABLE IF NOT EXISTS branch_merge_policy(
 namespace text NOT NULL REFERENCES namespaces(id), branch text NOT NULL, policy text NOT NULL,
 PRIMARY KEY(namespace,branch));
CREATE TABLE IF NOT EXISTS candidate_causality(
 namespace text NOT NULL REFERENCES namespaces(id), receipt text NOT NULL REFERENCES operations(receipt),
 unknown boolean NOT NULL, PRIMARY KEY(namespace,receipt));
CREATE TABLE IF NOT EXISTS conflicts(
 id text PRIMARY KEY, sequence bigserial UNIQUE NOT NULL,
 namespace text NOT NULL REFERENCES namespaces(id), branch text NOT NULL,
 principal text NOT NULL, replica text NOT NULL,
 receipt text NOT NULL REFERENCES operations(receipt), integration text NOT NULL,
 base_revision text NOT NULL, candidate_revision text NOT NULL, current_revision text NOT NULL,
 original_head text NOT NULL, current_head text NOT NULL,
 reason text NOT NULL CHECK(reason IN ('content','text_overlap','merge_budget','edit_delete','add_add','path_collision','competing_rename','directory_delete','metadata','unknown_causality','missing_base')),
 policy text NOT NULL CHECK(policy IN ('opaque','text')), entry text,
 payload text NOT NULL, digest text NOT NULL,
 FOREIGN KEY(namespace,replica,integration) REFERENCES operations(namespace,replica,operation),
 FOREIGN KEY(namespace,base_revision) REFERENCES revisions(namespace,revision),
 FOREIGN KEY(namespace,candidate_revision) REFERENCES revisions(namespace,revision),
 FOREIGN KEY(namespace,current_revision) REFERENCES revisions(namespace,revision));
CREATE UNIQUE INDEX IF NOT EXISTS conflicts_identity ON conflicts(namespace,integration,COALESCE(entry,''));
CREATE INDEX IF NOT EXISTS conflicts_listing ON conflicts(namespace,principal,sequence);
CREATE TABLE IF NOT EXISTS conflict_alternatives(
 id text PRIMARY KEY, conflict text NOT NULL REFERENCES conflicts(id),
 side text NOT NULL CHECK(side IN ('base','current','candidate')), revision text NOT NULL, entry text,
 UNIQUE(conflict,side));
CREATE TABLE IF NOT EXISTS conflict_resolutions(
 conflict text PRIMARY KEY REFERENCES conflicts(id), namespace text NOT NULL, replica text NOT NULL,
 operation text NOT NULL, revision text NOT NULL,
 FOREIGN KEY(namespace,replica,operation) REFERENCES operations(namespace,replica,operation),
 FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
-- Service-only provenance sidecar for merge/resolution revisions. Canonical descriptors and
-- projected views are unchanged; projections never enumerate this server-side lineage.
CREATE TABLE IF NOT EXISTS revision_provenance(
 namespace text NOT NULL, revision text NOT NULL, kind text NOT NULL CHECK(kind IN ('merge','resolution')),
 operation text NOT NULL, payload text NOT NULL, digest text NOT NULL,
 PRIMARY KEY(namespace,revision), FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
-- Alternative export views: re-authorized against current rights on every use.
ALTER TABLE views ADD COLUMN IF NOT EXISTS alternative text REFERENCES conflict_alternatives(id);
ALTER TABLE views ADD COLUMN IF NOT EXISTS alternative_entry text;
-- Ruling R16: conflicts hidden from the resolving caller are closed as superseded by the
-- resolution that left their entries at head values; their alternatives stay immutable.
ALTER TABLE conflict_resolutions ADD COLUMN IF NOT EXISTS superseded boolean NOT NULL DEFAULT false;
-- Ruling R21: namespace identity registry, every EntryId ever published in a shared revision
-- (seed, fast-forward, merge, resolution) of the namespace. Created and backfilled exactly once
-- (serialized across concurrently starting service processes) from the revisions that were
-- ever a branch head; every later publication registers its new identities in its commit.
DO $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtext('magus-fs namespace_entries'));
 IF to_regclass('namespace_entries') IS NULL THEN
  CREATE TABLE namespace_entries(
   namespace text NOT NULL REFERENCES namespaces(id), entry text NOT NULL,
   PRIMARY KEY(namespace,entry));
  INSERT INTO namespace_entries(namespace,entry)
  SELECT DISTINCT s.namespace, e->>'id'
  FROM (SELECT namespace,revision FROM branches
        UNION SELECT namespace,derived_revision FROM operations
         WHERE status=200 AND kind IN ('seed','integration','resolution') AND derived_revision IS NOT NULL
        UNION SELECT namespace,revision FROM revision_provenance) s
  JOIN revisions r ON r.namespace=s.namespace AND r.revision=s.revision
  CROSS JOIN LATERAL jsonb_array_elements(convert_from(r.descriptor,'UTF8')::jsonb #> '{tree,entries}') e;
 END IF;
END $$;
