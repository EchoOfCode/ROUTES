import { pool } from "@/lib/db";

const TABLE = "products";

export async function GET(request: Request) {
  const limit = parseInt(new URL(request.url).searchParams.get("limit") ?? "10", 10);
  const { rows } = await pool.query(`SELECT * FROM ${TABLE} LIMIT ${limit}`);
  return Response.json(rows);
}
