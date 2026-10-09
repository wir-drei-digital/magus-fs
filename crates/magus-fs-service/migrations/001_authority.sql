CREATE TABLE IF NOT EXISTS namespaces (id text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS principals (namespace text REFERENCES namespaces(id), id text, PRIMARY KEY(namespace,id));
CREATE TABLE IF NOT EXISTS groups (namespace text REFERENCES namespaces(id), id text, PRIMARY KEY(namespace,id));
CREATE TABLE IF NOT EXISTS group_members (namespace text, group_id text, principal text, PRIMARY KEY(namespace,group_id,principal), FOREIGN KEY(namespace,group_id) REFERENCES groups(namespace,id), FOREIGN KEY(namespace,principal) REFERENCES principals(namespace,id));
CREATE TABLE IF NOT EXISTS replicas (namespace text, id text, principal text NOT NULL, PRIMARY KEY(namespace,id), FOREIGN KEY(namespace,principal) REFERENCES principals(namespace,id));
CREATE TABLE IF NOT EXISTS credentials (
 id text PRIMARY KEY, token_hash text UNIQUE NOT NULL, namespace text NOT NULL, principal text NOT NULL, replica text NOT NULL,
 generation bigint NOT NULL DEFAULT 1, expires timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
 parent text REFERENCES credentials(id), parent_generation bigint,
 FOREIGN KEY(namespace,principal) REFERENCES principals(namespace,id), FOREIGN KEY(namespace,replica) REFERENCES replicas(namespace,id)
);
CREATE TABLE IF NOT EXISTS grants (credential text PRIMARY KEY REFERENCES credentials(id), actions text[] NOT NULL, branches text[] NOT NULL, prefixes text[] NOT NULL);
CREATE TABLE IF NOT EXISTS grant_audit (sequence bigserial PRIMARY KEY, namespace text NOT NULL REFERENCES namespaces(id), actor text NOT NULL REFERENCES credentials(id), target text NOT NULL REFERENCES credentials(id), action text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS upload_sessions (
 id text PRIMARY KEY, namespace text NOT NULL REFERENCES namespaces(id), credential text NOT NULL REFERENCES credentials(id), generation bigint NOT NULL,
 principal text NOT NULL, replica text NOT NULL, expires timestamptz NOT NULL, reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes BETWEEN 0 AND 536870912),
 reserved_objects bigint NOT NULL DEFAULT 0 CHECK(reserved_objects BETWEEN 0 AND 4096)
);
CREATE TABLE IF NOT EXISTS objects (
 namespace text NOT NULL REFERENCES namespaces(id), object_id text NOT NULL, generation text NOT NULL, storage_key text UNIQUE NOT NULL,
 size bigint NOT NULL CHECK(size BETWEEN 0 AND 1048576), state text NOT NULL CHECK(state IN ('uploading','ready','deleting','corrupt')),
 lease_until timestamptz NOT NULL, PRIMARY KEY(namespace,object_id), UNIQUE(namespace,object_id,generation)
);
CREATE TABLE IF NOT EXISTS session_objects (
 upload text NOT NULL REFERENCES upload_sessions(id), namespace text NOT NULL, object_id text NOT NULL, generation text NOT NULL, completed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(upload,object_id), FOREIGN KEY(namespace,object_id,generation) REFERENCES objects(namespace,object_id,generation)
);
