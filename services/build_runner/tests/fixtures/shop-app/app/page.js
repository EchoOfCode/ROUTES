import { pool } from "../lib/db";

export const dynamic = "force-dynamic";

export default async function Home() {
  const { rows } = await pool.query("SELECT count(*)::int AS n FROM products");
  return <main><h1>Fixture Shop</h1><p>{rows[0].n} products</p></main>;
}
