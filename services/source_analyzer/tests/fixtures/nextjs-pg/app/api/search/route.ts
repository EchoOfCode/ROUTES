import { NextRequest, NextResponse } from "next/server";
import { pool } from "@/lib/db";

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}
