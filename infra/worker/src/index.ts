/**
 * api.resqd.ai reverse proxy.
 *
 * Forwards all requests to the AWS API Gateway HTTP API for the resqd-api
 * Lambda, rewriting the Host header so API Gateway accepts them. Injects
 * an origin verification secret so the Lambda can reject requests that
 * bypass this Worker (i.e., direct API Gateway access).
 *
 * Also forwards the CF Access authenticated email so the Lambda can
 * enforce admin identity checks.
 */
export interface Env {
  UPSTREAM_HOST: string;
  ORIGIN_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Admin auth bounce — by the time we reach this handler, CF Access
    // has already authenticated the user and set the CF_Authorization
    // cookie on api.resqd.ai.  Just redirect back to the admin page so
    // subsequent cross-origin fetches carry the cookie.
    if (url.pathname === "/admin/bounce") {
      const returnUrl =
        url.searchParams.get("return_url") || "https://resqd.ai/admin/";
      // Only allow redirects to resqd.ai origins.
      if (!returnUrl.startsWith("https://resqd.ai/")) {
        return new Response("invalid return_url", { status: 400 });
      }
      return Response.redirect(returnUrl, 302);
    }

    url.hostname = env.UPSTREAM_HOST;
    url.protocol = "https:";
    url.port = "";

    // Copy headers, drop the ones that shouldn't be forwarded verbatim.
    const headers = new Headers(request.headers);
    headers.set("host", env.UPSTREAM_HOST);
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ray");
    headers.delete("cf-visitor");

    // Inject origin verification secret — Lambda rejects requests without this.
    headers.set("x-origin-secret", env.ORIGIN_SECRET);

    // Forward CF Access identity for admin auth at the Lambda layer.
    // (cf-access-authenticated-user-email is set by Cloudflare Access after auth)

    // Forward country for geo-blocking at Lambda.
    // (cf-ipcountry is set by Cloudflare edge)

    const proxied = new Request(url.toString(), {
      method: request.method,
      headers,
      body:
        request.method === "GET" || request.method === "HEAD"
          ? undefined
          : request.body,
      redirect: "manual",
    });

    return fetch(proxied);
  },
} satisfies ExportedHandler<Env>;
