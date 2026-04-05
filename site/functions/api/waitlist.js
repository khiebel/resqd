// RESQD waitlist capture — Cloudflare Pages Function
// Writes submissions to KV (WAITLIST) and fires a webhook to the RESQD
// watchdog on AWS (API Gateway → Lambda → DynamoDB hiebel-events + SES email).

export async function onRequestPost({ request, env }) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "https://resqd.ai",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  try {
    const ct = request.headers.get("content-type") || "";
    let body;
    if (ct.includes("application/json")) {
      body = await request.json();
    } else {
      const form = await request.formData();
      body = Object.fromEntries(form.entries());
    }

    const email  = String(body.email || "").trim().toLowerCase();
    const source = String(body.source || "landing").slice(0, 40);
    const note   = String(body.note   || "").slice(0, 500);

    const emailOk =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
    if (!emailOk) {
      return new Response(JSON.stringify({ ok: false, error: "invalid_email" }), {
        status: 400,
        headers: corsHeaders,
      });
    }

    // Honeypot — silent accept
    if (body.website) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: corsHeaders,
      });
    }

    const dedupeKey = `dedupe:${email}`;
    const existed = await env.WAITLIST.get(dedupeKey);

    const now     = new Date().toISOString();
    const ip      = request.headers.get("cf-connecting-ip") || "";
    const country = request.cf?.country || "";
    const ua      = request.headers.get("user-agent") || "";
    const ref     = request.headers.get("referer") || "";
    const id      = `${now}-${crypto.randomUUID().slice(0, 8)}`;

    if (!existed) {
      const entry = { id, email, source, note, ts: now, ip, country, ua, ref };
      await env.WAITLIST.put(`entry:${id}`, JSON.stringify(entry));
      await env.WAITLIST.put(dedupeKey, "1", {
        expirationTtl: 60 * 60 * 24 * 7,
      });
      const cur = parseInt((await env.WAITLIST.get("count:total")) || "0", 10);
      await env.WAITLIST.put("count:total", String(cur + 1));
    }

    // Fire webhook so Kevin gets instant notification.
    // Does not block the user response if webhook is slow.
    if (env.WATCHDOG_URL && env.WATCHDOG_SECRET && !existed) {
      try {
        await fetch(env.WATCHDOG_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-resqd-secret": env.WATCHDOG_SECRET,
          },
          body: JSON.stringify({ id, email, source, ip, country, ref, ua }),
          signal: AbortSignal.timeout(5000),
        });
      } catch (e) {
        // don't fail the user path
      }
    }

    return new Response(JSON.stringify({ ok: true, id, dedup: !!existed }), {
      status: 200,
      headers: corsHeaders,
    });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: "server_error" }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "https://resqd.ai",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}
