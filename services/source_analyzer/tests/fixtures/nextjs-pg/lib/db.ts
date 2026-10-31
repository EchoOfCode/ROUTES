import { Pool } from "pg";

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function findUserByName(name: string) {
  return pool.query(`SELECT id, email FROM users WHERE name = '${name}'`);
}

export async function findUserById(id: string) {
  return pool.query("SELECT id, email FROM users WHERE id = $1", [id]);
}
