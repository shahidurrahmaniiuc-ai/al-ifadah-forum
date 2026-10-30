const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" }
});

const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

async function sessionKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signSession(payload, secret) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await sessionKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + b64url(sig);
}

async function verifySession(token, secret) {
  if (!token || token.length > 2048) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  try {
    const key = await sessionKey(secret);
    const signature = Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(parts[0]));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const now = Math.floor(Date.now() / 1000);
    if (!payload.sub || payload.role !== "member" || !payload.exp || payload.exp <= now) return null;
    return payload;
  } catch { return null; }
}

async function getMember(env, id) {
  const endpoint = new URL("/rest/v1/members", env.SUPABASE_URL);
  endpoint.searchParams.set("select", "id,member_code,full_name,email,phone,units,is_active,nominee_name,nominee_phone,nominee_nid,nominee_relation");
  endpoint.searchParams.set("id", "eq." + id);
  endpoint.searchParams.set("is_active", "eq.true");
  endpoint.searchParams.set("limit", "1");
  const response = await fetch(endpoint, { headers: {
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    authorization: "Bearer " + env.SUPABASE_SERVICE_ROLE_KEY
  }});
  if (!response.ok) throw new Error("database");
  const rows = await response.json();
  return Array.isArray(rows) && rows.length === 1 ? rows[0] : null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const configured = env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY && env.MEMBER_SESSION_SECRET;
    if (url.pathname.startsWith("/api/") && !configured) {
      return json({ error: "সার্ভার কনফিগারেশন সম্পূর্ণ হয়নি।" }, 503);
    }

    if (url.pathname === "/api/member-login" && request.method === "POST") {
      let input;
      try { input = await request.json(); } catch { return json({ error: "অনুরোধটি সঠিক নয়।" }, 400); }
      const email = String(input.email || "").trim().toLowerCase();
      const phone = String(input.phone || "").replace(/[\s()-]/g, "");
      if (!email || !phone || email.length > 254 || phone.length > 40) {
        return json({ error: "ইমেইল ও মোবাইল নম্বর সঠিকভাবে দিন।" }, 400);
      }
      try {
        const endpoint = new URL("/rest/v1/members", env.SUPABASE_URL);
        endpoint.searchParams.set("select", "id,member_code,full_name");
        endpoint.searchParams.set("email", "eq." + email);
        endpoint.searchParams.set("phone", "eq." + phone);
        endpoint.searchParams.set("is_active", "eq.true");
        endpoint.searchParams.set("limit", "2");
        const response = await fetch(endpoint, { headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: "Bearer " + env.SUPABASE_SERVICE_ROLE_KEY
        }});
        if (!response.ok) return json({ error: "ডেটাবেসে সংযোগ করা যায়নি।" }, 503);
        const rows = await response.json();
        if (!Array.isArray(rows) || rows.length !== 1) return json({ error: "ইমেইল বা মোবাইল নম্বর মেলেনি।" }, 401);
        const member = rows[0];
        const now = Math.floor(Date.now() / 1000);
        const token = await signSession({ sub: member.id, role: "member", iat: now, exp: now + 1800 }, env.MEMBER_SESSION_SECRET);
        return json({ token, expires_in: 1800, member: { member_code: member.member_code, full_name: member.full_name } });
      } catch { return json({ error: "লগইন যাচাই করা যায়নি।" }, 503); }
    }

    if (url.pathname === "/api/member/me" && request.method === "GET") {
      const authorization = request.headers.get("authorization") || "";
      const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
      const session = await verifySession(token, env.MEMBER_SESSION_SECRET);
      if (!session) return json({ error: "সেশনটি মেয়াদোত্তীর্ণ বা বৈধ নয়। আবার লগইন করুন।" }, 401);
      try {
        const member = await getMember(env, session.sub);
        if (!member) return json({ error: "সদস্য অ্যাকাউন্ট সক্রিয় নেই।" }, 403);
        const headers = {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          authorization: "Bearer " + env.SUPABASE_SERVICE_ROLE_KEY
        };
        const readRows = async (table, select, filters = [], order = "") => {
          const endpoint = new URL("/rest/v1/" + table, env.SUPABASE_URL);
          endpoint.searchParams.set("select", select);
          for (const [key, value] of filters) endpoint.searchParams.set(key, value);
          if (order) endpoint.searchParams.set("order", order);
          endpoint.searchParams.set("limit", "500");
          const response = await fetch(endpoint, { headers });
          if (!response.ok) throw new Error("database");
          return response.json();
        };
        const [members, deposits, investments, plans, unitHistory] = await Promise.all([
          readRows("members", "id,member_code,full_name,email,phone,units,is_active,role,created_at,nominee_name,nominee_phone,nominee_nid,nominee_relation", [], "full_name.asc"),
          readRows("deposits", "member_id,amount,deposit_date,note", [], "deposit_date.desc"),
          readRows("investments", "title,amount,investment_date,investment_end_date,note", [], "investment_date.desc"),
          readRows("plans", "title,description,target_amount,status,created_at", [], "created_at.desc"),
          readRows("member_unit_history", "member_id,old_units,new_units,changed_at,note", [], "changed_at.desc")
        ]);
        return json({ member: {
          member_code: member.member_code, full_name: member.full_name,
          email: member.email, phone: member.phone, units: member.units,
          nominee: {
            name: member.nominee_name, phone: member.nominee_phone,
            nid: member.nominee_nid, relation: member.nominee_relation
          }
        }, members, deposits, investments, plans, unit_history: unitHistory });
      } catch { return json({ error: "সদস্যের তথ্য আনা যায়নি।" }, 503); }
    }

    return env.ASSETS.fetch(request);
  }
};
