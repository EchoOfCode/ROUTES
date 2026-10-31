import { pool } from "@/lib/db";

export async function GET(request: Request) {
  const client = await pool.connect();
  const form = await request.formData();
  const region = form.get("region");
  const res = await client.query("SELECT * FROM sales WHERE region = '" + region + "'");
  client.release();
  return Response.json(res.rows);
}
