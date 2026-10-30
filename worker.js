const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});

async function signSession(payload, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const body = btoa(String.fromCharCode(...enc.encode(JSON.stringify(payload))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  const signature = btoa(String.fromCharCode(...sig))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return body + "." + signature;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/member-login" && request.method === "POST") {
      if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY || !env.MEMBER_SESSION_SECRET) {
        return json({ error: "সার্ভার কনফিগারেশন সম্পূর্ণ হয়নি।" }, 503);
      }
      let input;
      try { input = await request.json(); } catch { return json({ error: "অনুরোধটি সঠিক নয়।" }, 400); }
      const email = String(input.email || "").trim().toLowerCase();
      const phone = String(input.phone || "").replace(/[\s()-]/g, "");
      if (!email || !phone || email.length > 254 || phone.length > 40) {
        return json({ error: "ইমেইল ও মোবাইল নম্বর সঠিকভাবে দিন।" }, 400);
      }
      const endpoint = new URL("/rest/v1/members", env.SUPABASE_URL);
      endpoint.searchParams.set("select", "id,member_code,full_name");
      endpoint.searchParams.set("email", "eq." + email);
      endpoint.searchParams.set("phone", "eq." + phone);
      endpoint.searchParams.set("is_active", "eq.true");
      endpoint.searchParams.set("limit", "2");
      const response = await fetch(endpoint, {
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: "Bearer " + env.SUPABASE_SERVICE_ROLE_KEY
        }
      });
      if (!response.ok) return json({ error: "লগইন যাচাই করা যায়নি।" }, 503);
      const rows = await response.json();
      if (!Array.isArray(rows) || rows.length !== 1) {
        return json({ error: "ইমেইল বা মোবাইল নম্বর মেলেনি।" }, 401);
      }
      const member = rows[0];
      const now = Math.floor(Date.now() / 1000);
      const token = await signSession({
        sub: member.id, role: "member", iat: now, exp: now + 1800
      }, env.MEMBER_SESSION_SECRET);
      return json({
        token,
        expires_in: 1800,
        member: { member_code: member.member_code, full_name: member.full_name }
      });
    }
    return env.ASSETS.fetch(request);
  }
};
