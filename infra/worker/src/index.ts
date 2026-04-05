/**
 * api.resqd.ai reverse proxy.
 *
 * Forwards all requests to the AWS API Gateway HTTP API for the resqd-api
 * Lambda, rewriting the Host header so API Gateway accepts them. Cloudflare
 * Access (attached separately to api.resqd.ai) gates who can reach this
 * Worker at all — service tokens or email SSO.
 */
export interface Env {
  UPSTREAM_HOST: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    url.hostname = env.UPSTREAM_HOST;
    url.protocol = "https:";
    url.port = "";

    // Copy headers, drop the ones that shouldn't be forwarded verbatim.
    const headers = new Headers(request.headers);
    headers.set("host", env.UPSTREAM_HOST);
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ipcountry");
    headers.delete("cf-ray");
    headers.delete("cf-visitor");
    // Cloudflare Access leaves these behind after authenticating — they're
    // fine to strip before forwarding to AWS.
    headers.delete("cf-access-authenticated-user-email");
    headers.delete("cf-access-jwt-assertion");

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
