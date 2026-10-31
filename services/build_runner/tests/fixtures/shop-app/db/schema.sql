CREATE TABLE products (
  id serial PRIMARY KEY,
  name text NOT NULL,
  price numeric(10, 2) NOT NULL,
  internal_note text
);
CREATE TABLE users (
  id serial PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL
);
