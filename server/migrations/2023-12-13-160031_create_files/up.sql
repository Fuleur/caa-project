CREATE TABLE files (
    id VARCHAR PRIMARY KEY, -- UUIDv4 of the file
    name BLOB,              -- name of the file [encrypted]
    mtime BIGINT,           -- last modification time
    sz INT,                 -- original file size
    data BLOB,              -- content [encrypted], empty if folder
    keyring INT             -- if folder, keyring of this folder
);