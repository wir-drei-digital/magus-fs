-- Additive immutable declarations/results; all pinned revisions retain object roots.
CREATE TABLE IF NOT EXISTS branch_validator_policy(
 namespace text NOT NULL REFERENCES namespaces(id), branch text NOT NULL, policy text NOT NULL,
 PRIMARY KEY(namespace,branch));
CREATE TABLE IF NOT EXISTS dependency_operations(
 namespace text NOT NULL REFERENCES namespaces(id), replica text NOT NULL, operation text NOT NULL,
 credential text NOT NULL REFERENCES credentials(id), principal text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('declaration','validation')), digest text NOT NULL,
 request text NOT NULL, result text NOT NULL, PRIMARY KEY(namespace,replica,operation));
CREATE TABLE IF NOT EXISTS declarations(
 id text PRIMARY KEY, namespace text NOT NULL, replica text NOT NULL, operation text NOT NULL,
 candidate text NOT NULL, branch text NOT NULL, payload text NOT NULL,
 UNIQUE(namespace,candidate),
 FOREIGN KEY(namespace,replica,operation) REFERENCES dependency_operations(namespace,replica,operation));
CREATE TABLE IF NOT EXISTS dependency_pins(
 declaration text NOT NULL REFERENCES declarations(id), namespace text NOT NULL, revision text NOT NULL,
 PRIMARY KEY(declaration,namespace,revision),
 FOREIGN KEY(namespace,revision) REFERENCES revisions(namespace,revision));
CREATE TABLE IF NOT EXISTS validations(
 id text PRIMARY KEY, namespace text NOT NULL, replica text NOT NULL, operation text NOT NULL,
 declaration text NOT NULL REFERENCES declarations(id), policy text NOT NULL,
 FOREIGN KEY(namespace,replica,operation) REFERENCES dependency_operations(namespace,replica,operation));
