CREATE TABLE sessions (
    token               VARCHAR PRIMARY KEY NOT NULL,
    user                VARCHAR NOT NULL,
    expiration_date     BIGINT NOT NULL,
    FOREIGN KEY(user) REFERENCES users(username)
);