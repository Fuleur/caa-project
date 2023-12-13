CREATE TABLE keys (
    target BLOB PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,                   -- [encrypted]
    keyring INTEGER NOT NULL,
    FOREIGN KEY(keyring) REFERENCES keyrings(id)
);