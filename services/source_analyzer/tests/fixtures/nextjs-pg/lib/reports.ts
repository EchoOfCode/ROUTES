import { pool } from "@/lib/db";

// Never called from a route handler in this fixture -> inconclusive.
export async function reportFor(table: string) {
  return pool.query("SELECT count(*) FROM " + table);
}
