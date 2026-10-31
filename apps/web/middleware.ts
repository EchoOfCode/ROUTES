import { NextResponse, type NextRequest } from "next/server";

// UX-only guard: avoids flashing app pages to signed-out visitors. The API
// enforces authentication and ownership on every request regardless.
const PUBLIC = ["/login", "/register"];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const hasSession = request.cookies.has("routes_session");
  if (!hasSession && !PUBLIC.some((p) => pathname.startsWith(p))) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = pathname === "/" ? "" : `?next=${encodeURIComponent(pathname)}`;
    return NextResponse.redirect(url);
  }
  // A present-but-expired cookie must still be able to reach /login, so
  // signed-in users are not bounced away from the auth pages here.
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
