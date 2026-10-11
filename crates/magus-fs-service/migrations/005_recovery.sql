-- Additive recovery records; no old descriptor/digest/provenance rewritten.
CREATE TABLE IF NOT EXISTS history_bindings(
 id text PRIMARY KEY, namespace text NOT NULL, branch text NOT NULL,
 credential text NOT NULL REFERENCES credentials(id), principal text NOT NULL, replica text NOT NULL,
 revision text NOT NULL, entry text NOT NULL, change text NOT NULL CHECK(change IN ('version')),
 UNIQUE(namespace,branch,credential,revision,entry),
 FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
CREATE TABLE IF NOT EXISTS history_cursors(
 id text PRIMARY KEY, namespace text NOT NULL REFERENCES namespaces(id),
 credential text NOT NULL REFERENCES credentials(id), principal text NOT NULL, replica text NOT NULL,
 view_id text NOT NULL REFERENCES views(id), offset_value bigint NOT NULL CHECK(offset_value>=0));
ALTER TABLE views ADD COLUMN IF NOT EXISTS history text REFERENCES history_bindings(id);
ALTER TABLE views ADD COLUMN IF NOT EXISTS history_entry text;
CREATE TABLE IF NOT EXISTS restoration_provenance(
 namespace text NOT NULL, revision text NOT NULL, history text NOT NULL REFERENCES history_bindings(id),
 operation text NOT NULL, payload text NOT NULL, digest text NOT NULL,
 PRIMARY KEY(namespace,revision), FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
CREATE TABLE IF NOT EXISTS change_retention(
 namespace text NOT NULL REFERENCES namespaces(id), branch text NOT NULL, floor bigint NOT NULL CHECK(floor>=0),
 PRIMARY KEY(namespace,branch));
CREATE TABLE IF NOT EXISTS gc_plans(
 token text PRIMARY KEY, namespace text NOT NULL REFERENCES namespaces(id), payload text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp());

-- Actual shared publication index. Merge private parents are never indexed as history.
DO $$ BEGIN
 PERFORM pg_advisory_xact_lock(hashtext('magus-fs published_entries'));
 IF to_regclass('published_entries') IS NULL THEN
 CREATE TABLE published_entries(
 sequence bigserial PRIMARY KEY, namespace text NOT NULL, branch text NOT NULL,
 revision text NOT NULL, entry text NOT NULL, UNIQUE(namespace,branch,revision,entry),
 FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
INSERT INTO published_entries(namespace,branch,revision,entry)
 SELECT p.namespace,p.branch,p.revision,e->>'id' FROM (
  SELECT namespace,name AS branch,revision FROM branches
  UNION SELECT o.namespace,o.branch,o.derived_revision FROM operations o
   WHERE o.status=200 AND o.kind IN ('seed','integration','resolution')
    AND NOT EXISTS(SELECT 1 FROM revision_provenance v WHERE v.namespace=o.namespace AND v.operation=o.operation AND v.kind='merge')
  UNION SELECT v.namespace,o.branch,v.revision FROM revision_provenance v JOIN operations o
   ON o.namespace=v.namespace AND o.operation=v.operation AND o.status=200
 ) p JOIN revisions r ON r.namespace=p.namespace AND r.revision=p.revision
 CROSS JOIN LATERAL jsonb_array_elements(convert_from(r.descriptor,'UTF8')::jsonb #> '{tree,entries}') e
 WHERE e #>> '{content,kind}'='file' ON CONFLICT DO NOTHING;
 END IF;
END $$;

CREATE INDEX IF NOT EXISTS published_entries_page ON published_entries(namespace,branch,sequence);
CREATE TABLE IF NOT EXISTS quarantined_generations(
 namespace text NOT NULL REFERENCES namespaces(id), object_id text NOT NULL, generation text NOT NULL,
 storage_key text UNIQUE NOT NULL, size bigint NOT NULL, state text NOT NULL,
 PRIMARY KEY(namespace,object_id,generation));

-- Durable ownership/resume for a proposed immutable repair generation. Unfinished
-- attempts remain retained; no unverified generation is a revision reference.
CREATE TABLE IF NOT EXISTS repair_attempts(
 namespace text NOT NULL REFERENCES namespaces(id), object_id text NOT NULL,
 source_generation text NOT NULL, generation text NOT NULL, storage_key text UNIQUE NOT NULL,
 state text NOT NULL CHECK(state IN ('prepared','installed')),
 PRIMARY KEY(namespace,object_id,source_generation));
