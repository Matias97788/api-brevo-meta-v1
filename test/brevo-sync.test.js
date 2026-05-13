const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { app, normalizePhone } = require("../src/server");

function makeJsonResponse({ status, data }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return data;
    }
  };
}

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        method: "GET",
        hostname: u.hostname,
        port: u.port,
        path: `${u.pathname}${u.search}`,
        headers: { Accept: "application/json" }
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          const parsed = body ? JSON.parse(body) : null;
          resolve({ status: res.statusCode || 0, data: parsed });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function withServer() {
  const server = http.createServer(app);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
          })
      });
    });
  });
}

test("normalizePhone normaliza números chilenos móviles a formato E.164", () => {
  assert.equal(normalizePhone("912345678"), "+56912345678");
  assert.equal(normalizePhone("56 9 1234 5678"), "+56912345678");
  assert.equal(normalizePhone("+56912345678"), "+56912345678");
  assert.equal(normalizePhone(""), null);
  assert.equal(normalizePhone("+56"), null);
});

test("brevo sync envía TELEFONO y LANDLINE_NUMBER con el mismo valor para ambos formularios", async () => {
  const originalFetch = global.fetch;
  const originalEnv = { ...process.env };

  process.env.META_ACCESS_TOKEN = "meta_token";
  process.env.BREVO_API_KEY = "brevo_key";

  const formIds = ["3270047599818919", "1504586737730429"];
  const phoneInput = "912345678";
  const expectedPhone = normalizePhone(phoneInput);

  assert.ok(expectedPhone);

  const brevoCalls = [];

  global.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input?.toString ? input.toString() : String(input);

    if (url.startsWith("https://graph.facebook.com/")) {
      const u = new URL(url);
      const parts = u.pathname.split("/").filter(Boolean);
      const id = parts[1];
      const isLeads = parts[2] === "leads";
      if (!isLeads || !formIds.includes(id)) {
        return makeJsonResponse({ status: 404, data: { error: { message: "not_found" } } });
      }

      return makeJsonResponse({
        status: 200,
        data: {
          data: [
            {
              id: `lead_${id}`,
              created_time: "2026-05-01T00:00:00+0000",
              ad_id: "ad_1",
              form_id: id,
              field_data: [
                { name: "email", values: ["test@example.com"] },
                { name: "telefono", values: [phoneInput] }
              ]
            }
          ],
          paging: {}
        }
      });
    }

    if (url === "https://api.brevo.com/v3/contacts") {
      const body = init?.body ? JSON.parse(String(init.body)) : null;
      brevoCalls.push({ url, method: init?.method || "GET", body });
      return makeJsonResponse({ status: 201, data: { id: 1 } });
    }

    return makeJsonResponse({ status: 500, data: { error: { message: `unexpected_fetch:${url}` } } });
  };

  const { baseUrl, close } = await withServer();
  try {
    for (const formId of formIds) {
      brevoCalls.length = 0;
      const r = await httpGetJson(`${baseUrl}/brevo/sync/forms/${formId}/leads?list_id=22&max_contacts=1`);
      assert.equal(r.status, 200);
      assert.equal(r.data?.ok, true);

      assert.equal(brevoCalls.length, 1);
      const call = brevoCalls[0];
      assert.equal(call.method, "POST");

      assert.deepEqual(call.body?.listIds, [22]);
      assert.equal(call.body?.attributes?.TELEFONO, expectedPhone);
      assert.equal(call.body?.attributes?.LANDLINE_NUMBER, expectedPhone);
      assert.equal(call.body?.attributes?.SMS, expectedPhone);
    }
  } finally {
    await close();
    global.fetch = originalFetch;
    for (const k of Object.keys(process.env)) {
      if (!Object.prototype.hasOwnProperty.call(originalEnv, k)) delete process.env[k];
    }
    for (const [k, v] of Object.entries(originalEnv)) {
      process.env[k] = v;
    }
  }
});
