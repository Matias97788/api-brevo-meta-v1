const express = require("express");
const dotenv = require("dotenv");
const crypto = require("crypto");

dotenv.config();

const app = express();

// Permite recibir JSON en requests (body) con un límite de tamaño razonable
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);

// Endpoint simple para verificar que la API está viva
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

function verifyMetaSignature(req) {
  const secret = process.env.META_APP_SECRET;
  if (!secret) return true;

  const header = req.headers["x-hub-signature-256"];
  if (typeof header !== "string" || !header.startsWith("sha256=")) return false;

  const raw = Buffer.isBuffer(req.rawBody)
    ? req.rawBody
    : Buffer.from(JSON.stringify(req.body || {}));

  const digest = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  const expected = `sha256=${digest}`;

  const a = Buffer.from(expected);
  const b = Buffer.from(header);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.get("/webhook/meta", (req, res) => {
  const mode = typeof req.query["hub.mode"] === "string" ? req.query["hub.mode"] : "";
  const token =
    typeof req.query["hub.verify_token"] === "string" ? req.query["hub.verify_token"] : "";
  const challenge =
    typeof req.query["hub.challenge"] === "string" ? req.query["hub.challenge"] : "";

  const verifyToken = process.env.META_VERIFY_TOKEN;
  if (mode === "subscribe" && verifyToken && token === verifyToken && challenge) {
    return res.status(200).send(challenge);
  }

  return res.sendStatus(403);
});

app.post("/webhook/meta", async (req, res) => {
  if (!verifyMetaSignature(req)) return res.sendStatus(401);

  const metaToken = process.env.META_ACCESS_TOKEN;
  const brevoKey = process.env.BREVO_API_KEY;

  if (!metaToken) {
    return res.status(500).json({ ok: false, error: "Falta META_ACCESS_TOKEN en el entorno." });
  }
  if (!brevoKey) {
    return res.status(500).json({ ok: false, error: "Falta BREVO_API_KEY en el entorno." });
  }

  const listIdRaw = process.env.BREVO_LIST_ID;
  const listIdNumber = listIdRaw ? Number.parseInt(String(listIdRaw), 10) : null;
  const validListId = Number.isInteger(listIdNumber) && listIdNumber > 0;

  const entries = Array.isArray(req.body?.entry) ? req.body.entry : [];
  const tasks = [];

  for (const entry of entries) {
    const changes = Array.isArray(entry?.changes) ? entry.changes : [];
    for (const change of changes) {
      if (change?.field !== "leadgen") continue;
      const value = change?.value || {};
      const leadgenId = value?.leadgen_id ? String(value.leadgen_id) : "";
      const formId = value?.form_id ? String(value.form_id) : "";
      if (!leadgenId) continue;

      tasks.push(
        (async () => {
          let accessToken = metaToken;
          if (formId) {
            const resolved = await resolveFormPageAccessToken(formId, metaToken);
            if (resolved.ok && resolved.page?.access_token) accessToken = resolved.page.access_token;
          }

          const leadUrl = new URL(`https://graph.facebook.com/v19.0/${leadgenId}`);
          leadUrl.searchParams.set("access_token", accessToken);
          leadUrl.searchParams.set("fields", "id,created_time,ad_id,form_id,field_data");

          let leadResult = await fetchGraphJson(leadUrl);
          if (!leadResult.ok && accessToken !== metaToken) {
            leadUrl.searchParams.set("access_token", metaToken);
            leadResult = await fetchGraphJson(leadUrl);
          }
          if (!leadResult.ok) return;

          const lead = leadResult.data;
          const data = normalizeLeadFields(lead?.field_data);
          const email = String(data?.correo || "").trim();
          if (!email) return;

          const attributes = {};
          if (data?.Nombre) attributes.FIRSTNAME = String(data.Nombre);
          if (data?.Apellido) attributes.LASTNAME = String(data.Apellido);
          if (data?.telefono) attributes.PHONE = String(data.telefono);
          if (data?.web) attributes.WEB = String(data.web);
          if (data?.selecciona_un_servicio) attributes.SERVICIO = String(data.selecciona_un_servicio);
          if (data?.["¿cúentanos_en_qué_necesitas_ayuda?"])
            attributes.MENSAJE = String(data["¿cúentanos_en_qué_necesitas_ayuda?"]);

          await brevoUpsertContact({
            apiKey: brevoKey,
            email,
            attributes,
            listId: validListId ? listIdNumber : null
          });
        })()
      );
    }
  }

  try {
    await Promise.all(tasks);
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "Error procesando webhook",
      details: err?.message || String(err)
    });
  }

  return res.json({ ok: true });
});

// Obtiene el access token de Meta desde:
// 1) Header: Authorization: Bearer <token>
// 2) Variable de entorno: META_ACCESS_TOKEN
function getMetaAccessToken(req) {
  const auth = req.headers.authorization;
  if (typeof auth === "string") {
    const [scheme, value] = auth.split(" ");
    if (scheme?.toLowerCase() === "bearer" && value) return value.trim();
  }
  if (process.env.META_ACCESS_TOKEN) return process.env.META_ACCESS_TOKEN;
  return null;
}

// Llama a Graph API /me para validar el token y traer datos básicos del usuario
// Ejemplo: GET /meta/me?fields=id,name
app.get("/meta/me", async (req, res) => {
  const token = getMetaAccessToken(req);
  if (!token) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  // Campos que quieres pedirle a Meta. Si no envías ?fields=..., usa id,name
  const fields =
    typeof req.query.fields === "string" && req.query.fields.trim()
      ? req.query.fields.trim()
      : "id,name";

  // Construye la URL a Meta con query params
  const url = new URL("https://graph.facebook.com/v19.0/me");
  url.searchParams.set("fields", fields);
  url.searchParams.set("access_token", token);

  try {
    // Node 18+ trae fetch global. Si tu Node es más viejo, habría que agregar un polyfill.
    const metaRes = await fetch(url, {
      headers: { Accept: "application/json" }
    });
    const data = await metaRes.json().catch(() => null);

    // Si Meta devuelve error, lo reenviamos con su status para debug controlado
    if (!metaRes.ok) {
      return res.status(metaRes.status).json({
        ok: false,
        error: "Meta API error",
        details: data
      });
    }

    return res.json({ ok: true, data });
  } catch (err) {
    // Errores de red / excepciones inesperadas
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta",
      details: err?.message || String(err)
    });
  }
});

async function fetchGraphAll(url) {
  const items = [];
  let next = url.toString();

  while (next) {
    const res = await fetch(next, { headers: { Accept: "application/json" } });
    const data = await res.json().catch(() => null);

    if (!res.ok) {
      return { ok: false, status: res.status, data };
    }

    items.push(...((data && data.data) || []));
    next = (data && data.paging && data.paging.next) || null;
  }

  return { ok: true, items };
}

async function fetchGraphJson(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  const data = await res.json().catch(() => null);
  if (!res.ok) return { ok: false, status: res.status, data };
  return { ok: true, data };
}

function cleanMetaFieldName(value) {
  return String(value ?? "")
    .trim()
    .replace(/^"+|"+$/g, "");
}

function normalizeLeadFieldKey(rawKey) {
  const key = cleanMetaFieldName(rawKey);

  const exactMap = {
    Oscar: "Nombre",
    Pinto: "Apellido",
    "+569": "telefono",
    "www.": "web",
    "xxxxxx@nomanadas.com": "correo"
  };

  if (exactMap[key]) return exactMap[key];

  const lower = key.toLowerCase();
  if (lower.includes("@")) return "correo";
  if (lower.startsWith("www") || lower.startsWith("http")) return "web";
  if (/^\+?\d[\d\s()-]*$/.test(key)) return "telefono";

  return key;
}

function normalizeLeadFields(fieldData) {
  const output = {};

  for (const entry of Array.isArray(fieldData) ? fieldData : []) {
    const key = normalizeLeadFieldKey(entry?.name);
    const values = Array.isArray(entry?.values) ? entry.values : [];
    if (!key) continue;
    if (values.length === 0) continue;
    output[key] = values.length === 1 ? values[0] : values;
  }

  const orderedKeys = [
    "Nombre",
    "Apellido",
    "correo",
    "telefono",
    "web",
    "selecciona_un_servicio",
    "¿cúentanos_en_qué_necesitas_ayuda?"
  ];

  const ordered = {};
  for (const k of orderedKeys) {
    if (Object.prototype.hasOwnProperty.call(output, k)) ordered[k] = output[k];
  }
  for (const [k, v] of Object.entries(output)) {
    if (!Object.prototype.hasOwnProperty.call(ordered, k)) ordered[k] = v;
  }

  return ordered;
}

function getBrevoApiKey(req) {
  const auth = req.headers.authorization;
  if (typeof auth === "string") {
    const [scheme, value] = auth.split(" ");
    if (scheme?.toLowerCase() === "brevo" && value) return value.trim();
  }
  if (process.env.BREVO_API_KEY) return process.env.BREVO_API_KEY;
  return null;
}

async function brevoUpsertContact({ apiKey, email, attributes, listId }) {
  const url = "https://api.brevo.com/v3/contacts";

  const body = {
    email,
    updateEnabled: true
  };

  if (listId) body.listIds = [Number.parseInt(String(listId), 10)];
  if (attributes && Object.keys(attributes).length > 0) body.attributes = attributes;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "api-key": apiKey
    },
    body: JSON.stringify(body)
  });

  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

async function brevoAddContactsToList({ apiKey, listId, emails }) {
  const url = `https://api.brevo.com/v3/contacts/lists/${listId}/contacts/add`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "api-key": apiKey
    },
    body: JSON.stringify({ emails })
  });

  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

async function resolveFormPageAccessToken(formId, userToken) {
  const pagesUrl = new URL("https://graph.facebook.com/v19.0/me/accounts");
  pagesUrl.searchParams.set("access_token", userToken);
  pagesUrl.searchParams.set("fields", "id,name,access_token");

  const pagesResult = await fetchGraphAll(pagesUrl);
  if (!pagesResult.ok) return { ok: false, status: pagesResult.status, data: pagesResult.data };

  for (const page of pagesResult.items) {
    const pageId = page?.id;
    const pageToken = page?.access_token;
    if (!pageId || !pageToken) continue;

    const pageFormsUrl = new URL(
      `https://graph.facebook.com/v19.0/${pageId}/leadgen_forms`
    );
    pageFormsUrl.searchParams.set("access_token", pageToken);
    pageFormsUrl.searchParams.set("fields", "id");

    const pageFormsResult = await fetchGraphAll(pageFormsUrl);
    if (!pageFormsResult.ok) continue;

    const hasForm = pageFormsResult.items.some((f) => f?.id === formId);
    if (hasForm) return { ok: true, page };
  }

  return { ok: true, page: null };
}

// ============================================
// Lista todos los formularios de Lead Ads
// de todas las páginas que administra el token
// Ejemplo: GET /meta/forms
//          GET /meta/forms?page_id=123456789  (filtrar por página específica)
// ============================================
app.get("/meta/forms", async (req, res) => {
  const token = getMetaAccessToken(req);
  if (!token) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  try {
    let pages = [];

    if (typeof req.query.page_id === "string" && req.query.page_id.trim()) {
      const pageId = req.query.page_id.trim();
      const pageUrl = new URL(`https://graph.facebook.com/v19.0/${pageId}`);
      pageUrl.searchParams.set("access_token", token);
      pageUrl.searchParams.set("fields", "id,name,access_token");

      const pageResult = await fetchGraphJson(pageUrl);
      if (!pageResult.ok) {
        return res.status(pageResult.status).json({
          ok: false,
          error: "Error al obtener la página",
          details: pageResult.data
        });
      }

      pages = [pageResult.data];
    } else {
      const pagesUrl = new URL("https://graph.facebook.com/v19.0/me/accounts");
      pagesUrl.searchParams.set("access_token", token);
      pagesUrl.searchParams.set("fields", "id,name,access_token");

      const pagesResult = await fetchGraphAll(pagesUrl);
      if (!pagesResult.ok) {
        return res.status(pagesResult.status).json({
          ok: false,
          error: "Error al obtener páginas",
          details: pagesResult.data
        });
      }

      pages = pagesResult.items;
      const count = pages.map((p) => p.id).filter(Boolean).length;
      console.log(`📄 Páginas encontradas: ${count}`);
    }

    const todosLosFormularios = [];
    const errors = [];

    for (const page of pages) {
      const pageId = page?.id;
      if (!pageId) continue;

      const pageToken = page?.access_token || token;
      const formsUrl = new URL(
        `https://graph.facebook.com/v19.0/${pageId}/leadgen_forms`
      );
      formsUrl.searchParams.set("access_token", pageToken);
      formsUrl.searchParams.set(
        "fields",
        "id,name,status,created_time,leads_count"
      );

      const formsResult = await fetchGraphAll(formsUrl);
      if (!formsResult.ok) {
        errors.push({
          page_id: pageId,
          message: formsResult.data?.error?.message || "Error desconocido",
          code: formsResult.data?.error?.code,
          error_subcode: formsResult.data?.error?.error_subcode
        });
        continue;
      }

      const formularios = formsResult.items.map((f) => ({
        ...f,
        page_id: pageId
      }));

      todosLosFormularios.push(...formularios);
    }

    return res.json({
      ok: true,
      total: todosLosFormularios.length,
      forms: todosLosFormularios,
      errors
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta",
      details: err?.message || String(err)
    });
  }
});

// ============================================
// Devuelve los datos de un formulario específico
// Ejemplo: GET /meta/forms/3270047599818919
// ============================================
app.get("/meta/forms/:form_id", async (req, res) => {
  const token = getMetaAccessToken(req);
  if (!token) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  const formId = String(req.params.form_id || "").trim();
  if (!formId) {
    return res.status(400).json({ ok: false, error: "Falta form_id." });
  }

  const fields =
    typeof req.query.fields === "string" && req.query.fields.trim()
      ? req.query.fields.trim()
      : "id,name,status,created_time,leads_count,locale,questions";

  const formUrl = new URL(`https://graph.facebook.com/v19.0/${formId}`);
  formUrl.searchParams.set("fields", fields);
  formUrl.searchParams.set("access_token", token);

  try {
    const directResult = await fetchGraphJson(formUrl);
    if (directResult.ok) {
      return res.json({ ok: true, form: directResult.data });
    }

    const pagesUrl = new URL("https://graph.facebook.com/v19.0/me/accounts");
    pagesUrl.searchParams.set("access_token", token);
    pagesUrl.searchParams.set("fields", "id,name,access_token");

    const pagesResult = await fetchGraphAll(pagesUrl);
    if (!pagesResult.ok) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener el formulario",
        details: directResult.data
      });
    }

    let matchedPage = null;
    for (const page of pagesResult.items) {
      const pageId = page?.id;
      if (!pageId) continue;

      const pageToken = page?.access_token;
      if (!pageToken) continue;

      const pageFormsUrl = new URL(
        `https://graph.facebook.com/v19.0/${pageId}/leadgen_forms`
      );
      pageFormsUrl.searchParams.set("access_token", pageToken);
      pageFormsUrl.searchParams.set("fields", "id");

      const pageFormsResult = await fetchGraphAll(pageFormsUrl);
      if (!pageFormsResult.ok) continue;

      const hasForm = pageFormsResult.items.some((f) => f?.id === formId);
      if (hasForm) {
        matchedPage = page;
        break;
      }
    }

    if (!matchedPage) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener el formulario",
        details: directResult.data
      });
    }

    const pageFormUrl = new URL(`https://graph.facebook.com/v19.0/${formId}`);
    pageFormUrl.searchParams.set("fields", fields);
    pageFormUrl.searchParams.set("access_token", matchedPage.access_token);

    const pageResult = await fetchGraphJson(pageFormUrl);
    if (!pageResult.ok) {
      return res.status(pageResult.status).json({
        ok: false,
        error: "No se pudo obtener el formulario con token de página",
        details: pageResult.data
      });
    }

    return res.json({
      ok: true,
      form: pageResult.data,
      page: { id: matchedPage.id, name: matchedPage.name }
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta",
      details: err?.message || String(err)
    });
  }
});

app.get("/meta/forms/:form_id/leads", async (req, res) => {
  const token = getMetaAccessToken(req);
  if (!token) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  const formId = String(req.params.form_id || "").trim();
  if (!formId) {
    return res.status(400).json({ ok: false, error: "Falta form_id." });
  }

  const fields =
    typeof req.query.fields === "string" && req.query.fields.trim()
      ? req.query.fields.trim()
      : "id,created_time,ad_id,form_id,field_data";

  const limit =
    typeof req.query.limit === "string" && req.query.limit.trim()
      ? Number.parseInt(req.query.limit.trim(), 10)
      : null;

  const tryFetchLeads = async (accessToken) => {
    const leadsUrl = new URL(
      `https://graph.facebook.com/v19.0/${formId}/leads`
    );
    leadsUrl.searchParams.set("access_token", accessToken);
    leadsUrl.searchParams.set("fields", fields);
    if (Number.isFinite(limit) && limit > 0) {
      leadsUrl.searchParams.set("limit", String(limit));
    }
    return fetchGraphAll(leadsUrl);
  };

  try {
    const directResult = await tryFetchLeads(token);
    if (directResult.ok) {
      return res.json({
        ok: true,
        total: directResult.items.length,
        leads: directResult.items
      });
    }

    const pagesUrl = new URL("https://graph.facebook.com/v19.0/me/accounts");
    pagesUrl.searchParams.set("access_token", token);
    pagesUrl.searchParams.set("fields", "id,name,access_token");

    const pagesResult = await fetchGraphAll(pagesUrl);
    if (!pagesResult.ok) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads",
        details: directResult.data
      });
    }

    let matchedPage = null;
    for (const page of pagesResult.items) {
      const pageId = page?.id;
      if (!pageId) continue;

      const pageToken = page?.access_token;
      if (!pageToken) continue;

      const pageFormsUrl = new URL(
        `https://graph.facebook.com/v19.0/${pageId}/leadgen_forms`
      );
      pageFormsUrl.searchParams.set("access_token", pageToken);
      pageFormsUrl.searchParams.set("fields", "id");

      const pageFormsResult = await fetchGraphAll(pageFormsUrl);
      if (!pageFormsResult.ok) continue;

      const hasForm = pageFormsResult.items.some((f) => f?.id === formId);
      if (hasForm) {
        matchedPage = page;
        break;
      }
    }

    if (!matchedPage?.access_token) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads",
        details: directResult.data
      });
    }

    const pageResult = await tryFetchLeads(matchedPage.access_token);
    if (!pageResult.ok) {
      return res.status(pageResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads con token de página",
        details: pageResult.data
      });
    }

    return res.json({
      ok: true,
      total: pageResult.items.length,
      leads: pageResult.items,
      page: { id: matchedPage.id, name: matchedPage.name }
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta",
      details: err?.message || String(err)
    });
  }
});

app.get("/meta/forms/:form_id/leads/normalized", async (req, res) => {
  const token = getMetaAccessToken(req);
  if (!token) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  const formId = String(req.params.form_id || "").trim();
  if (!formId) {
    return res.status(400).json({ ok: false, error: "Falta form_id." });
  }

  const limit =
    typeof req.query.limit === "string" && req.query.limit.trim()
      ? Number.parseInt(req.query.limit.trim(), 10)
      : null;

  const tryFetchLeads = async (accessToken) => {
    const leadsUrl = new URL(
      `https://graph.facebook.com/v19.0/${formId}/leads`
    );
    leadsUrl.searchParams.set("access_token", accessToken);
    leadsUrl.searchParams.set("fields", "id,created_time,ad_id,form_id,field_data");
    if (Number.isFinite(limit) && limit > 0) {
      leadsUrl.searchParams.set("limit", String(limit));
    }
    return fetchGraphAll(leadsUrl);
  };

  try {
    const directResult = await tryFetchLeads(token);
    if (directResult.ok) {
      const normalized = directResult.items.map((lead) => ({
        id: lead?.id,
        created_time: lead?.created_time,
        ad_id: lead?.ad_id,
        form_id: lead?.form_id,
        data: normalizeLeadFields(lead?.field_data)
      }));

      return res.json({
        ok: true,
        total: normalized.length,
        leads: normalized
      });
    }

    const pagesUrl = new URL("https://graph.facebook.com/v19.0/me/accounts");
    pagesUrl.searchParams.set("access_token", token);
    pagesUrl.searchParams.set("fields", "id,name,access_token");

    const pagesResult = await fetchGraphAll(pagesUrl);
    if (!pagesResult.ok) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads",
        details: directResult.data
      });
    }

    let matchedPage = null;
    for (const page of pagesResult.items) {
      const pageId = page?.id;
      if (!pageId) continue;

      const pageToken = page?.access_token;
      if (!pageToken) continue;

      const pageFormsUrl = new URL(
        `https://graph.facebook.com/v19.0/${pageId}/leadgen_forms`
      );
      pageFormsUrl.searchParams.set("access_token", pageToken);
      pageFormsUrl.searchParams.set("fields", "id");

      const pageFormsResult = await fetchGraphAll(pageFormsUrl);
      if (!pageFormsResult.ok) continue;

      const hasForm = pageFormsResult.items.some((f) => f?.id === formId);
      if (hasForm) {
        matchedPage = page;
        break;
      }
    }

    if (!matchedPage?.access_token) {
      return res.status(directResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads",
        details: directResult.data
      });
    }

    const pageResult = await tryFetchLeads(matchedPage.access_token);
    if (!pageResult.ok) {
      return res.status(pageResult.status).json({
        ok: false,
        error: "No se pudo obtener los leads con token de página",
        details: pageResult.data
      });
    }

    const normalized = pageResult.items.map((lead) => ({
      id: lead?.id,
      created_time: lead?.created_time,
      ad_id: lead?.ad_id,
      form_id: lead?.form_id,
      data: normalizeLeadFields(lead?.field_data)
    }));

    return res.json({
      ok: true,
      total: normalized.length,
      leads: normalized,
      page: { id: matchedPage.id, name: matchedPage.name }
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta",
      details: err?.message || String(err)
    });
  }
});

app.get("/brevo/sync/forms/:form_id/leads", async (req, res) => {
  const metaToken = getMetaAccessToken(req);
  if (!metaToken) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Meta. Configura META_ACCESS_TOKEN en el entorno o envía Authorization: Bearer <token>."
    });
  }

  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }

  const formId = String(req.params.form_id || "").trim();
  if (!formId) {
    return res.status(400).json({ ok: false, error: "Falta form_id." });
  }

  const dryRun =
    typeof req.query.dry_run === "string" &&
    ["1", "true", "yes"].includes(req.query.dry_run.trim().toLowerCase());

  const limit =
    typeof req.query.limit === "string" && req.query.limit.trim()
      ? Number.parseInt(req.query.limit.trim(), 10)
      : null;

  const listId =
    typeof req.query.list_id === "string" && req.query.list_id.trim()
      ? req.query.list_id.trim()
      : process.env.BREVO_LIST_ID;

  const listIdNumber = listId ? Number.parseInt(String(listId), 10) : null;
  const validListId = Number.isInteger(listIdNumber) && listIdNumber > 0;

  const tryFetchLeads = async (accessToken) => {
    const leadsUrl = new URL(
      `https://graph.facebook.com/v19.0/${formId}/leads`
    );
    leadsUrl.searchParams.set("access_token", accessToken);
    leadsUrl.searchParams.set("fields", "id,created_time,ad_id,form_id,field_data");
    if (Number.isFinite(limit) && limit > 0) {
      leadsUrl.searchParams.set("limit", String(limit));
    }
    return fetchGraphAll(leadsUrl);
  };

  try {
    let leadsResult = await tryFetchLeads(metaToken);
    let page = null;

    if (!leadsResult.ok) {
      const resolved = await resolveFormPageAccessToken(formId, metaToken);
      if (!resolved.ok) {
        return res.status(resolved.status).json({
          ok: false,
          error: "No se pudo resolver la página del formulario",
          details: resolved.data
        });
      }

      page = resolved.page;
      if (!page?.access_token) {
        return res.status(leadsResult.status).json({
          ok: false,
          error: "No se pudo obtener leads (sin token de página)",
          details: leadsResult.data
        });
      }

      leadsResult = await tryFetchLeads(page.access_token);
    }

    if (!leadsResult.ok) {
      return res.status(leadsResult.status).json({
        ok: false,
        error: "No se pudo obtener leads",
        details: leadsResult.data
      });
    }

    const normalizedLeads = leadsResult.items.map((lead) => ({
      id: lead?.id,
      created_time: lead?.created_time,
      ad_id: lead?.ad_id,
      form_id: lead?.form_id,
      data: normalizeLeadFields(lead?.field_data)
    }));

    const candidates = normalizedLeads
      .map((lead) => {
        const email = String(lead?.data?.correo || "").trim();
        if (!email) return null;

        const attributes = {};
        if (lead?.data?.Nombre) attributes.FIRSTNAME = String(lead.data.Nombre);
        if (lead?.data?.Apellido) attributes.LASTNAME = String(lead.data.Apellido);
        if (lead?.data?.telefono) attributes.PHONE = String(lead.data.telefono);
        if (lead?.data?.web) attributes.WEB = String(lead.data.web);
        if (lead?.data?.selecciona_un_servicio)
          attributes.SERVICIO = String(lead.data.selecciona_un_servicio);
        if (lead?.data?.["¿cúentanos_en_qué_necesitas_ayuda?"])
          attributes.MENSAJE = String(lead.data["¿cúentanos_en_qué_necesitas_ayuda?"]);

        return { lead, email, attributes };
      })
      .filter(Boolean);

    if (dryRun) {
      return res.json({
        ok: true,
        dry_run: true,
        total_leads: normalizedLeads.length,
        total_contacts: candidates.length,
        sample: candidates.slice(0, 5).map((c) => ({
          email: c.email,
          attributes: c.attributes
        })),
        page: page ? { id: page.id, name: page.name } : null
      });
    }

    const results = [];
    for (const c of candidates) {
      const firstAttempt = await brevoUpsertContact({
        apiKey: brevoKey,
        email: c.email,
        attributes: c.attributes,
        listId: validListId ? listIdNumber : null
      });

      if (firstAttempt.ok) {
        results.push({
          email: c.email,
          status: firstAttempt.status,
          details: firstAttempt.data
        });
        continue;
      }

      const fallbackAttempt = await brevoUpsertContact({
        apiKey: brevoKey,
        email: c.email,
        attributes: {},
        listId: validListId ? listIdNumber : null
      });

      if (fallbackAttempt.ok) {
        results.push({
          email: c.email,
          status: fallbackAttempt.status,
          note: "created_without_attributes",
          details: fallbackAttempt.data
        });
        continue;
      }

      results.push({
        email: c.email,
        status: firstAttempt.status,
        error: firstAttempt.data
      });
    }

    let listAdd = null;
    if (validListId && candidates.length > 0) {
      const emails = candidates.map((c) => c.email);
      const chunks = [];
      for (let i = 0; i < emails.length; i += 150) {
        chunks.push(emails.slice(i, i + 150));
      }

      const listAddResults = [];
      for (const chunk of chunks) {
        const r = await brevoAddContactsToList({
          apiKey: brevoKey,
          listId: listIdNumber,
          emails: chunk
        });
        listAddResults.push(r);
      }

      const ok = listAddResults.every((r) => r.ok);
      listAdd = {
        ok,
        list_id: listIdNumber,
        batches: listAddResults.map((r) => ({
          ok: r.ok,
          status: r.status,
          details: r.data
        }))
      };
    }

    return res.json({
      ok: true,
      total_leads: normalizedLeads.length,
      total_contacts: candidates.length,
      list_id: validListId ? listIdNumber : null,
      results,
      list_add: listAdd,
      page: page ? { id: page.id, name: page.name } : null
    });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "No se pudo conectar a Meta/Brevo",
      details: err?.message || String(err)
    });
  }
});

const port = Number.parseInt(process.env.PORT || "3000", 10);

// Solo levanta el servidor si ejecutas este archivo directo (node src/server.js).
// Si lo importas desde otro archivo, no auto-levanta.
if (require.main === module) {
  app.listen(port, () => {
    process.stdout.write(`API escuchando en http://localhost:${port}\n`);
  });
}

// Exporta app para tests o para montarla desde otro entrypoint
module.exports = { app };
