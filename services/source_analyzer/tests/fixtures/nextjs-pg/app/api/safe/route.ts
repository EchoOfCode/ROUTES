import { pool } from "@/lib/db";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const name = url.searchParams.get("name");
  const { rows } = await pool.query("SELECT * FROM products WHERE name = $1", [name]);
  const other = await pool.query({ text: "SELECT * FROM tags WHERE label = $1", values: [name] });
  return Response.json({ rows, other: other.rows });
}
