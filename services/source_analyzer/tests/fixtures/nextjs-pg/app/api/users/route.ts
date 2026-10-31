import { NextResponse } from "next/server";
import { findUserByName, findUserById } from "@/lib/db";

export async function POST(request: Request) {
  const { username, id } = await request.json();
  const byName = await findUserByName(username);
  const byId = await findUserById(id);
  return NextResponse.json({ byName: byName.rows, byId: byId.rows });
}
