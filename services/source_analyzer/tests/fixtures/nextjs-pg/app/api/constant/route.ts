import { pool } from "@/lib/db";

const STATUS = "active";

export async function GET() {
  const { rows } = await pool.query(`SELECT * FROM products WHERE status = '${STATUS}'`);
  return Response.json(rows);
}
