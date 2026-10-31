import { pool } from "@/lib/db";

export async function GET(request: Request) {
  const sort = new URL(request.url).searchParams.get("sort") ?? "name";
  const column = ["name", "price", "created_at"].includes(sort) ? sort : "name";
  const { rows } = await pool.query(`SELECT * FROM products ORDER BY ${column}`);
  return Response.json(rows);
}
