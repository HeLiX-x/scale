CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ip_pools (
    ip INET PRIMARY KEY,
    allocated BOOLEAN NOT NULL,
    device_id INTEGER REFERENCES devices(id),
    allocated_at TIMESTAMPTZ
);

CREATE TABLE peer_relations (
    id SERIAL PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    peer_id INTEGER NOT NULL REFERENCES devices(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);