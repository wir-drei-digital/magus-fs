-- Immutable publication evidence. Never infer historical mappings from candidate IDs.
CREATE TABLE IF NOT EXISTS publication_results (
 namespace text NOT NULL,
 branch text NOT NULL,
 receipt text NOT NULL,
 head text NOT NULL,
 operation text NOT NULL,
 replica text NOT NULL,
 submitted_revision text NOT NULL,
 published_revision text NOT NULL,
 PRIMARY KEY(namespace,receipt),
 UNIQUE(namespace,branch,head),
 FOREIGN KEY(namespace,replica,operation) REFERENCES operations(namespace,replica,operation),
 FOREIGN KEY(receipt) REFERENCES operations(receipt),
 -- submitted_revision is the exact receipt digest, not necessarily a stored full revision.
 -- Legacy candidates and restore projections must keep their existing publication semantics.
 FOREIGN KEY(namespace,published_revision) REFERENCES revisions(namespace,revision)
);
