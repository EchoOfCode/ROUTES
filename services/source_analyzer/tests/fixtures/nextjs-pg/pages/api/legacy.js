const { Pool } = require("pg");
const db = new Pool();

export default async function handler(req, res) {
  if (req.method === "GET") {
    const result = await db.query("SELECT * FROM orders WHERE customer = '" + req.query.customer + "'");
    return res.status(200).json(result.rows);
  }
  res.status(405).end();
}
