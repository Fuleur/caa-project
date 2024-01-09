CREATE TABLE keys (
    target VARCHAR PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,                   -- [encrypted]
    keyring_id INTEGER NOT NULL,
    FOREIGN KEY(keyring_id) REFERENCES keyrings(id),
    FOREIGN KEY(target) REFERENCES files(id)
);