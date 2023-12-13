CREATE TABLE files (
    name BLOB PRIMARY KEY,  -- name of the file (including path) [encrypted]
    mtime INT,              -- last modification time
    sz INT,                 -- original file size
    data BLOB,              -- content [encrypted]
    keyring INT             -- if folder, keyring of this folder
);