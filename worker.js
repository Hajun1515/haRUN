// Cloudflare Worker: penjaga client_secret Strava + proxy API (menghindari masalah CORS).
// Variabel yang harus diisi di dashboard Cloudflare (Settings > Variables):
//   STRAVA_CLIENT_ID      (teks)
//   STRAVA_CLIENT_SECRET  (Secret / terenkripsi)
//   ALLOWED_ORIGIN        (mis. https://namaakun.github.io  -- tanpa garis miring di akhir, tanpa path)

const RL = ['X-RateLimit-Limit', 'X-RateLimit-Usage', 'X-ReadRateLimit-Limit', 'X-ReadRateLimit-Usage'];
const API_ALLOW = ['athlete', 'athlete/activities']; // hanya endpoint yang dibutuhkan

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Expose-Headers': RL.join(', '),
      'Vary': 'Origin',
    };
    // Tolak semua yang bukan berasal dari situs kamu sendiri
    if (req.headers.get('Origin') !== env.ALLOWED_ORIGIN) return new Response('Forbidden', { status: 403 });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const url = new URL(req.url);
    const json = (body, status = 200, extra = {}) =>
      new Response(body, { status, headers: { ...cors, 'Content-Type': 'application/json', ...extra } });

    // Tukar kode otorisasi -> token (login pertama)
    if (req.method === 'POST' && url.pathname === '/token') {
      const { code } = await req.json();
      return tokenCall(env, { code, grant_type: 'authorization_code' }, json);
    }
    // Perbarui access token (berlaku 6 jam) memakai refresh token
    if (req.method === 'POST' && url.pathname === '/refresh') {
      const { refresh_token } = await req.json();
      return tokenCall(env, { refresh_token, grant_type: 'refresh_token' }, json);
    }
    // Proxy GET ke API Strava
    if (req.method === 'GET' && url.pathname.startsWith('/api/')) {
      const path = url.pathname.slice(5);
      if (!API_ALLOW.includes(path)) return new Response('Not allowed', { status: 404, headers: cors });
      const r = await fetch('https://www.strava.com/api/v3/' + path + url.search, {
        headers: { Authorization: req.headers.get('Authorization') || '' },
      });
      const extra = {};
      for (const k of RL) { const v = r.headers.get(k); if (v) extra[k] = v; }
      return json(r.body, r.status, extra);
    }
    return new Response('Not found', { status: 404, headers: cors });
  },
};

async function tokenCall(env, params, json) {
  const r = await fetch('https://www.strava.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.STRAVA_CLIENT_ID,
      client_secret: env.STRAVA_CLIENT_SECRET,
      ...params,
    }),
  });
  return json(await r.text(), r.status);
}
