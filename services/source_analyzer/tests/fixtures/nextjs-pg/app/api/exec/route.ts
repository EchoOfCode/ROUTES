import { exec } from "child_process";

export async function GET(request: Request) {
  const host = new URL(request.url).searchParams.get("host");
  exec(`ping -c 1 ${host}`, () => {});
  exec("uptime", () => {});
  return Response.json({ ok: true });
}
