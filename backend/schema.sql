-- Run this once against your NeonDB database (via the Neon SQL editor,
-- or `psql "$DATABASE_URL" -f schema.sql`) before starting the server.

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password TEXT NOT NULL,          -- stores the AES-encrypted password, never plaintext
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
