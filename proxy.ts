/**
 * Runs on every request. Two jobs:
 *   1. Refresh the Supabase session cookie so it never silently expires mid-session.
 *   2. Redirect signed-out visitors to /login, and signed-in visitors away from /login.
 *
 * Named `proxy.ts` per Next.js 16 — this file convention was renamed from "Middleware" to
 * "Proxy" in this version; the function and behaviour are the same as before.
 *
 * This is an optimistic, request-time gate — the CRM's role-based nav is a UI convenience, not
 * security. Once RLS policies are live (see supabase/migrations/0001_kcred_schema.sql), the
 * database enforces who can read what regardless of what this file does; this just keeps
 * signed-out visitors off every page.
 */
import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

// The cron route authenticates with CRON_SECRET inside its route handler. It must reach that
// handler without a Supabase browser session because Vercel's scheduler is not a signed-in user.
const PUBLIC_PATHS = ["/login", "/reset-password", "/api/cron/recurring-tasks"];

export async function proxy(request: NextRequest) {
  // An isolated sample-data studio for local review; never available in production.
  if (process.env.NODE_ENV === "development" && request.nextUrl.pathname === "/report-preview") {
    return NextResponse.next();
  }
  // Until .env.local has real Supabase credentials, auth is not configured yet — pass every
  // request through unchanged rather than crashing the whole app on every navigation. Remove
  // this guard once NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY are set for real.
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY) {
    return NextResponse.next();
  }

  let response = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options),
          );
        },
      },
    },
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const isPublicPath = PUBLIC_PATHS.some((path) => request.nextUrl.pathname.startsWith(path));

  if (!user && !isPublicPath) {
    const redirectUrl = new URL("/login", request.url);
    redirectUrl.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(redirectUrl);
  }

  if (user && request.nextUrl.pathname.startsWith("/login")) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Run on every path except static assets and Next internals, so a signed-out user cannot
     * reach any page — including ones added later — without this file seeing the request.
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|mp3|ogg|wav|m4a)$).*)",
  ],
};
