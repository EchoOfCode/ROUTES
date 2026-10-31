import { NextResponse } from "next/server";
import { pool } from "../../../lib/db";

export const dynamic = "force-dynamic";

// Deliberately vulnerable (fixture): user input is interpolated into SQL.
export async function GET(request) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  try {
    const result = await pool.query(`SELECT id, name, price FROM products WHERE name ILIKE '%${q}%' ORDER BY id`);
    return NextResponse.json(result.rows);
  } catch (e) {
    return NextResponse.json({ error: "query failed" }, { status: 500 });
  }
}
