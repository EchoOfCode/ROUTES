import { NextResponse } from "next/server";
import { pool } from "../../../lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await pool.query("SELECT 1");
    return NextResponse.json({ ok: true, database: true });
  } catch (e) {
    return NextResponse.json({ ok: false, database: false }, { status: 503 });
  }
}
