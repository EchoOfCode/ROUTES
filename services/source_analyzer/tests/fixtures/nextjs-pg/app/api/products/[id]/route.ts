import { pool } from "../../../../lib/db";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  let sql = "SELECT * FROM products WHERE id = ";
  sql += params.id;
  const { rows } = await pool.query(sql);
  return Response.json(rows[0] ?? null);
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await pool.query("DELETE FROM products WHERE id = $1", [params.id]);
  return new Response(null, { status: 204 });
}
