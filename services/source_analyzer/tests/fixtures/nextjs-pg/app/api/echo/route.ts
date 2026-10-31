import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get("name") ?? "";
  return new Response(`<p>Hello ${name}</p>`, { headers: { "content-type": "text/html" } });
}
