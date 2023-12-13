CREATE TABLE users (
    username    VARCHAR PRIMARY KEY NOT NULL,
    password    BLOB NOT NULL,
    pub_key     BLOB NOT NULL,
    priv_key    BLOB NOT NULL,
    keyring     INT NOT NULL,
    FOREIGN KEY(keyring) REFERENCES keyrings(i)
);