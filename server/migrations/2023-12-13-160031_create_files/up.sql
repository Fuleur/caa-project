CREATE TABLE files (
    id VARCHAR PRIMARY KEY NOT NULL, -- UUIDv4 of the file
    name VARCHAR NOT NULL,           -- name of the file [encrypted]
    mtime BIGINT,           -- last modification time
    sz INT,                 -- original file size
    data BLOB,              -- content [encrypted], empty if folder
    keyring_id INTEGER,     -- if folder, keyring of this folder
    FOREIGN KEY(keyring_id) REFERENCES keyrings(id)
);