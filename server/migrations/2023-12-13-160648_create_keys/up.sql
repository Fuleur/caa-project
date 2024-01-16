CREATE TABLE keys (
    id INTEGER PRIMARY KEY NOT NULL,
    target VARCHAR NOT NULL,                            -- file/folder UUID
    key BLOB NOT NULL,                                  -- [encrypted]
    keyring_id INTEGER NOT NULL,
    FOREIGN KEY(keyring_id) REFERENCES keyrings(id),
    FOREIGN KEY(target) REFERENCES files(id)
);