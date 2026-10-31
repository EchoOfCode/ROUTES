import { Client } from "pg";

export const POST = async (req: Request) => {
  const body = await req.json();
  const client = new Client();
  await client.connect();
  const out = await client.query(body.sql);
  await client.end();
  return Response.json(out.rows);
};
