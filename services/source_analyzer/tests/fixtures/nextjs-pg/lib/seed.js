// Seed data. Stored password hashes are not usable credentials and must not be
// reported as hardcoded secrets; the plaintext SMTP password below must be.
export const users = [
  { email: "demo@nova.local", password_hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" },
  { email: "ops@nova.local", passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" },
];

export const smtp = { host: "smtp.nova.local", password: "Winter2024Launch!" };
