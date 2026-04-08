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

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function getCronToken(req) {
  const fromHeader = req.headers["x-cron-token"];
  if (typeof fromHeader === "string" && fromHeader.trim()) return fromHeader.trim();
  if (typeof req.query.cron_token === "string" && req.query.cron_token.trim())
    return req.query.cron_token.trim();
  return null;
}

function requireCronAuthIfConfigured(req, res) {
  const expected = process.env.CRON_TOKEN;
  if (!expected) return true;
  const provided = getCronToken(req);
  if (!provided) return false;
  return safeEqual(provided, expected);
}

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
          if (data?.Nombre) attributes.NOMBRE = String(data.Nombre);
          if (data?.Apellido) attributes.APELLIDOS = String(data.Apellido);
          const phone = normalizePhone(data?.telefono);
          if (phone) attributes.TELEFONO = phone;
          if (phone) attributes.SMS = phone;
          if (data?.web) attributes.URL_SITIO = String(data.web);
          if (data?.selecciona_un_servicio) attributes.SERVICIOS = String(data.selecciona_un_servicio);
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

app.get("/brevo/contacts/:email", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }
  const email = String(req.params.email || "").trim();
  if (!email) return res.status(400).json({ ok: false, error: "Falta email." });
  const r = await brevoGetContact({ apiKey: brevoKey, email });
  return res.status(r.ok ? 200 : r.status).json({ ok: r.ok, data: r.data });
});

app.get("/brevo/attributes", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }
  const r = await brevoGetContactAttributes({ apiKey: brevoKey });
  return res.status(r.ok ? 200 : r.status).json({ ok: r.ok, data: r.data });
});

app.get("/brevo/lists/:list_id/contacts", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }
  const listId = String(req.params.list_id || "").trim();
  if (!listId) return res.status(400).json({ ok: false, error: "Falta list_id." });

  const limitRaw = typeof req.query.limit === "string" ? req.query.limit.trim() : "";
  const offsetRaw = typeof req.query.offset === "string" ? req.query.offset.trim() : "";
  const limit = limitRaw ? Number.parseInt(limitRaw, 10) : null;
  const offset = offsetRaw ? Number.parseInt(offsetRaw, 10) : null;

  const allRaw = typeof req.query.all === "string" ? req.query.all.trim().toLowerCase() : "";
  const all = ["1", "true", "yes"].includes(allRaw);

  if (all) {
    const r = await brevoGetAllContactsInList({
      apiKey: brevoKey,
      listId,
      pageLimit: Number.isFinite(limit) && limit > 0 ? limit : 500
    });
    return res.status(r.ok ? 200 : r.status).json({ ok: r.ok, data: r.data });
  }

  const r = await brevoGetContactsInList({
    apiKey: brevoKey,
    listId,
    limit: Number.isFinite(limit) && limit > 0 ? limit : null,
    offset: Number.isFinite(offset) && offset >= 0 ? offset : null
  });
  return res.status(r.ok ? 200 : r.status).json({ ok: r.ok, data: r.data });
});

app.post("/brevo/contacts/attributes", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }

  const emails = extractEmailsFromBody(req.body);
  if (emails.length === 0) {
    return res.status(400).json({
      ok: false,
      error: "No se encontraron emails en el JSON. Envia { emails: [...] } o { contacts: [...] }."
    });
  }

  const maxRaw = typeof req.query.max === "string" ? req.query.max.trim() : "";
  const max = maxRaw ? Number.parseInt(maxRaw, 10) : null;
  const cap = Number.isFinite(max) && max > 0 ? Math.min(max, 200) : 50;
  const selected = emails.slice(0, cap);

  const perContact = [];
  const attributeKeys = new Set();

  for (const email of selected) {
    const r = await brevoGetContact({ apiKey: brevoKey, email });
    if (r.ok && r.data && typeof r.data === "object") {
      const attrs = r.data.attributes && typeof r.data.attributes === "object" ? r.data.attributes : {};
      for (const k of Object.keys(attrs)) attributeKeys.add(k);
      perContact.push({ email, ok: true, attributes: attrs });
    } else {
      perContact.push({ email, ok: false, status: r.status, error: r.data });
    }
  }

  return res.json({
    ok: true,
    total_requested: emails.length,
    total_processed: selected.length,
    attribute_keys: Array.from(attributeKeys).sort(),
    contacts: perContact
  });
});

app.post("/brevo/lists/:list_id/contacts/attributes", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }
  const listId = String(req.params.list_id || "").trim();
  if (!listId) return res.status(400).json({ ok: false, error: "Falta list_id." });

  const limitRaw = typeof req.query.limit === "string" ? req.query.limit.trim() : "";
  const offsetRaw = typeof req.query.offset === "string" ? req.query.offset.trim() : "";
  const limit = limitRaw ? Number.parseInt(limitRaw, 10) : null;
  const offset = offsetRaw ? Number.parseInt(offsetRaw, 10) : null;

  let emails = extractEmailsFromBody(req.body);
  if (emails.length === 0) {
    const listRes = await brevoGetContactsInList({
      apiKey: brevoKey,
      listId,
      limit: Number.isFinite(limit) && limit > 0 ? limit : 50,
      offset: Number.isFinite(offset) && offset >= 0 ? offset : 0
    });
    if (!listRes.ok) {
      return res
        .status(listRes.status)
        .json({ ok: false, error: "No se pudo obtener contactos de la lista", details: listRes.data });
    }

    const contacts = Array.isArray(listRes.data?.contacts) ? listRes.data.contacts : [];
    emails = contacts
      .map((c) => (c?.email ? String(c.email).trim() : ""))
      .filter(Boolean);
  }

  if (emails.length === 0) {
    return res.status(400).json({
      ok: false,
      error:
        "No se encontraron emails ni en el JSON ni en la lista. Envia { emails: [...] } o revisa list_id."
    });
  }

  const maxRaw = typeof req.query.max === "string" ? req.query.max.trim() : "";
  const max = maxRaw ? Number.parseInt(maxRaw, 10) : null;
  const cap = Number.isFinite(max) && max > 0 ? Math.min(max, 200) : Math.min(emails.length, 50);
  const selected = emails.slice(0, cap);

  const perContact = [];
  const attributeKeys = new Set();

  for (const email of selected) {
    const r = await brevoGetContact({ apiKey: brevoKey, email });
    if (r.ok && r.data && typeof r.data === "object") {
      const attrs = r.data.attributes && typeof r.data.attributes === "object" ? r.data.attributes : {};
      for (const k of Object.keys(attrs)) attributeKeys.add(k);
      perContact.push({ email, ok: true, attributes: attrs });
    } else {
      perContact.push({ email, ok: false, status: r.status, error: r.data });
    }
  }

  return res.json({
    ok: true,
    list_id: listId,
    total_requested: emails.length,
    total_processed: selected.length,
    attribute_keys: Array.from(attributeKeys).sort(),
    contacts: perContact
  });
});

app.post("/brevo/lists/:list_id/repair", async (req, res) => {
  if (!requireCronAuthIfConfigured(req, res)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }

  const listId = String(req.params.list_id || "").trim();
  if (!listId) return res.status(400).json({ ok: false, error: "Falta list_id." });

  const dryRun =
    typeof req.query.dry_run === "string" &&
    ["1", "true", "yes"].includes(req.query.dry_run.trim().toLowerCase());

  const emailsFromBody = extractEmailsFromBody(req.body);
  const useProvidedEmails = emailsFromBody.length > 0;

  let emails = emailsFromBody;
  if (!useProvidedEmails) {
    const listRes = await brevoGetAllContactsInList({ apiKey: brevoKey, listId, pageLimit: 500 });
    if (!listRes.ok) {
      return res
        .status(listRes.status)
        .json({ ok: false, error: "No se pudo obtener contactos de la lista", details: listRes.data });
    }
    const contacts = Array.isArray(listRes.data?.contacts) ? listRes.data.contacts : [];
    emails = contacts
      .map((c) => (c?.email ? String(c.email).trim() : ""))
      .filter(Boolean);
  }

  const results = [];
  for (const email of emails) {
    const contactRes = await brevoGetContact({ apiKey: brevoKey, email });
    if (!contactRes.ok || !contactRes.data || typeof contactRes.data !== "object") {
      results.push({
        email,
        ok: false,
        status: contactRes.status,
        error: contactRes.data
      });
      continue;
    }

    const attrs =
      contactRes.data.attributes && typeof contactRes.data.attributes === "object"
        ? contactRes.data.attributes
        : {};

    const repair = repairBrevoAttributes({ email, attributes: attrs });
    if (!repair.changed) {
      results.push({ email, ok: true, changed: false, patch: {} });
      continue;
    }

    if (dryRun) {
      results.push({ email, ok: true, changed: true, patch: repair.patch });
      continue;
    }

    const updateRes = await brevoUpsertContact({
      apiKey: brevoKey,
      email,
      attributes: repair.patch,
      listId: null
    });

    results.push({
      email,
      ok: updateRes.ok,
      changed: true,
      patch: repair.patch,
      status: updateRes.status,
      details: updateRes.data
    });
  }

  const changed = results.filter((r) => r.ok && r.changed).length;
  const failed = results.filter((r) => !r.ok).length;

  return res.json({
    ok: true,
    list_id: listId,
    dry_run: dryRun,
    total: results.length,
    changed,
    failed,
    results
  });
});

app.post("/brevo/contacts/upsert", async (req, res) => {
  const brevoKey = getBrevoApiKey(req);
  if (!brevoKey) {
    return res.status(400).json({
      ok: false,
      error:
        "Falta el token de Brevo. Configura BREVO_API_KEY en el entorno o envía Authorization: Brevo <api_key>."
    });
  }
  const email = String(req.body?.email || "").trim();
  if (!email) return res.status(400).json({ ok: false, error: "Falta email." });
  const listIdRaw =
    typeof req.body?.list_id === "string" && req.body.list_id.trim()
      ? req.body.list_id.trim()
      : process.env.BREVO_LIST_ID;
  const listIdNumber = listIdRaw ? Number.parseInt(String(listIdRaw), 10) : null;
  const validListId = Number.isInteger(listIdNumber) && listIdNumber > 0;
  const attrs = req.body?.attributes && typeof req.body.attributes === "object" ? req.body.attributes : {};
  const attributes = { ...attrs };
  if (attributes.phone && !attributes.SMS) {
    attributes.SMS = String(attributes.phone);
    delete attributes.phone;
  }
  if (attributes.TELEFONO) {
    const p = normalizePhone(attributes.TELEFONO);
    if (p) attributes.TELEFONO = p;
    else delete attributes.TELEFONO;
  }
  if (attributes.SMS) {
    const p = normalizePhone(attributes.SMS);
    if (p) attributes.SMS = p;
    else delete attributes.SMS;
  }
  const r = await brevoUpsertContact({
    apiKey: brevoKey,
    email,
    attributes,
    listId: validListId ? listIdNumber : null
  });
  return res.status(r.ok ? 200 : r.status).json({ ok: r.ok, data: r.data });
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
  const lower = key.toLowerCase().replace(/\s+/g, "_");
  if (["email", "e_mail", "correo", "mail"].includes(lower)) return "correo";
  if (
    ["phone_number", "phone", "telefono", "mobile_phone", "contact_phone_number"].includes(lower)
  )
    return "telefono";
  if (["website", "web", "url"].includes(lower)) return "web";
  if (["first_name", "nombre", "name_first"].includes(lower)) return "Nombre";
  if (["last_name", "apellido", "surname", "name_last"].includes(lower)) return "Apellido";
  if (["full_name", "name", "nombre_completo"].includes(lower)) return "NombreCompleto";
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

  if (
    typeof output.Nombre !== "string" &&
    typeof output.Apellido !== "string" &&
    typeof output.NombreCompleto !== "string"
  ) {
    const reserved = new Set([
      "Nombre",
      "Apellido",
      "NombreCompleto",
      "correo",
      "telefono",
      "web",
      "selecciona_un_servicio",
      "¿cúentanos_en_qué_necesitas_ayuda?"
    ]);
    const candidates = Object.entries(output)
      .filter(([k, v]) => !reserved.has(k) && typeof v === "string" && v.trim())
      .map(([k, v]) => ({ key: k, value: v.trim() }));

    const looksLikeFullName = (s) => {
      const parts = s.split(/\s+/).filter(Boolean);
      if (parts.length < 2) return false;
      if (s.length < 4) return false;
      if (/@/.test(s)) return false;
      if (/^\+?\d[\d\s()-]*$/.test(s)) return false;
      return /[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/.test(s);
    };

    const fullName = candidates.find((c) => looksLikeFullName(c.value));
    if (fullName) {
      output.NombreCompleto = fullName.value;
      delete output[fullName.key];
    } else {
      const looksLikeSingleNameWord = (s) => {
        if (s.length < 2) return false;
        if (/@/.test(s)) return false;
        if (s.startsWith("http") || s.startsWith("www.")) return false;
        if (/^\+?\d[\d\s()-]*$/.test(s)) return false;
        const parts = s.split(/\s+/).filter(Boolean);
        if (parts.length !== 1) return false;
        return /^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ'’-]+$/.test(parts[0]);
      };

      const nameWords = candidates.filter((c) => looksLikeSingleNameWord(c.value));
      if (nameWords.length >= 2) {
        output.Nombre = nameWords[0].value;
        output.Apellido = nameWords[1].value;
        delete output[nameWords[0].key];
        delete output[nameWords[1].key];
      } else if (nameWords.length === 1) {
        output.Nombre = nameWords[0].value;
        delete output[nameWords[0].key];
      }
    }
  }

  if (typeof output.NombreCompleto === "string") {
    const parts = output.NombreCompleto.trim().split(/\s+/);
    const first = parts[0] || "";
    const last = parts.slice(1).join(" ") || "";
    if (first && !Object.prototype.hasOwnProperty.call(output, "Nombre")) {
      output.Nombre = first;
    }
    if (last && !Object.prototype.hasOwnProperty.call(output, "Apellido")) {
      output.Apellido = last;
    }
    delete output.NombreCompleto;
  }

  if (typeof output.Apellido === "string") {
    const reserved = new Set([
      "Nombre",
      "Apellido",
      "correo",
      "telefono",
      "web",
      "selecciona_un_servicio",
      "¿cúentanos_en_qué_necesitas_ayuda?"
    ]);
    const extraSurname = Object.entries(output)
      .filter(([k, v]) => !reserved.has(k) && typeof v === "string" && v.trim())
      .map(([k, v]) => ({ key: k, value: v.trim() }))
      .find((c) => {
        if (c.value.split(/\s+/).filter(Boolean).length !== 1) return false;
        if (/@/.test(c.value)) return false;
        if (/^\+?\d[\d\s()-]*$/.test(c.value)) return false;
        return /[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/.test(c.value);
      });

    if (extraSurname) {
      const current = output.Apellido.trim();
      if (current && !current.includes(extraSurname.value)) {
        output.Apellido = `${current} ${extraSurname.value}`.trim();
      }
      delete output[extraSurname.key];
    }
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

function normalizePhone(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;

  let s = raw.replace(/[^\d+]/g, "");
  if (s.startsWith("00")) s = `+${s.slice(2)}`;

  if (s.startsWith("+")) {
    const digits = s.slice(1).replace(/\D/g, "");
    if (!digits) return null;
    let normalizedDigits = digits;
    if (digits.length > 11 && digits.includes("569")) {
      const idx = digits.lastIndexOf("569");
      if (idx >= 0 && idx + 11 <= digits.length) normalizedDigits = digits.slice(idx, idx + 11);
    }

    const out = `+${normalizedDigits}`;
    if (out.startsWith("+56")) {
      if (out.length !== 12) return null;
      if (!out.startsWith("+569")) return null;
    } else if (out.length < 11) {
      return null;
    }
    return out;
  }

  s = s.replace(/\D/g, "");
  if (!s) return null;

  if (s.startsWith("569") && s.length === 11) return `+${s}`;
  if (s.startsWith("56") && s.length === 11) return `+${s}`;
  if (s.length === 9 && s.startsWith("9")) return `+56${s}`;

  return null;
}

function isValidEmail(value) {
  const s = String(value || "").trim();
  if (!s) return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(s);
}

function repairBrevoAttributes({ email, attributes }) {
  const patch = {};
  const lowerEmail = String(email || "").trim().toLowerCase();

  const get = (k) => {
    const v = attributes && Object.prototype.hasOwnProperty.call(attributes, k) ? attributes[k] : null;
    if (v === null || v === undefined) return null;
    const s = String(v).trim();
    return s ? s : null;
  };

  const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || "").trim());
  const isUrlLike = (v) => {
    const s = String(v || "").trim();
    if (!s) return false;
    if (isEmail(s)) return false;
    if (normalizePhone(s)) return false;
    if (/\s/.test(s)) return false;
    if (s.startsWith("http://") || s.startsWith("https://") || s.startsWith("www.")) return true;
    if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\/.*)?$/.test(s)) return true;
    return false;
  };

  const knownServices = new Set([
    "paid_media",
    "desarrollo",
    "consultoría_de_marketing",
    "social_media",
    "email_marketing",
    "data_y_análisis",
    "consultoria_de_marketing",
    "data_y_analisis"
  ]);

  const isServiceLike = (v) => {
    const s = String(v || "").trim();
    if (!s) return false;
    if (isEmail(s)) return false;
    if (isUrlLike(s)) return false;
    if (normalizePhone(s)) return false;
    const lower = s.toLowerCase();
    if (knownServices.has(lower)) return true;
    if (/^[a-záéíóúüñ_]+$/i.test(s) && s.includes("_") && s.length <= 40) return true;
    return false;
  };

  const maybeMovePhone = (value, sourceKey) => {
    const p = normalizePhone(value);
    if (!p) return false;
    const current = get("TELEFONO");
    if (!current || normalizePhone(current) !== p) patch.TELEFONO = p;
    const sms = get("SMS");
    if (!sms || normalizePhone(sms) !== p) patch.SMS = p;
    patch[sourceKey] = "";
    return true;
  };

  const url = get("URL_SITIO");
  if (url && isEmail(url) && lowerEmail && url.toLowerCase() === lowerEmail) patch.URL_SITIO = "";
  if (url && normalizePhone(url)) {
    maybeMovePhone(url, "URL_SITIO");
  }

  const telefono = get("TELEFONO");
  if (telefono) {
    const p = normalizePhone(telefono);
    if (p) {
      if (telefono !== p) patch.TELEFONO = p;
    } else {
      patch.TELEFONO = null;
    }
  }

  const sms = get("SMS");
  if (sms) {
    const p = normalizePhone(sms);
    if (p) {
      if (sms !== p) patch.SMS = p;
    } else {
      patch.SMS = null;
    }
  }

  const servicios = get("SERVICIOS");
  if (servicios) {
    if (normalizePhone(servicios)) {
      maybeMovePhone(servicios, "SERVICIOS");
    } else if (isUrlLike(servicios)) {
      const currentUrl = get("URL_SITIO");
      if (!currentUrl || isEmail(currentUrl)) patch.URL_SITIO = servicios;
      patch.SERVICIOS = "";
    }
  }

  const nombre = get("NOMBRE");
  if (nombre) {
    if (isUrlLike(nombre)) {
      const currentUrl = get("URL_SITIO");
      if (!currentUrl || isEmail(currentUrl)) patch.URL_SITIO = nombre;
      patch.NOMBRE = "";
    } else if (isServiceLike(nombre)) {
      const currentService = get("SERVICIOS");
      if (!currentService || isUrlLike(currentService) || normalizePhone(currentService)) patch.SERVICIOS = nombre;
      patch.NOMBRE = "";
    }
  }

  const changed = Object.keys(patch).length > 0;
  return { changed, patch };
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

async function brevoGetContact({ apiKey, email }) {
  const url = `https://api.brevo.com/v3/contacts/${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "api-key": apiKey
    }
  });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

async function brevoGetContactAttributes({ apiKey }) {
  const url = "https://api.brevo.com/v3/contacts/attributes";
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "api-key": apiKey
    }
  });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

async function brevoGetContactsInList({ apiKey, listId, limit, offset }) {
  const url = new URL(`https://api.brevo.com/v3/contacts/lists/${encodeURIComponent(listId)}/contacts`);
  if (Number.isFinite(limit) && limit > 0) url.searchParams.set("limit", String(limit));
  if (Number.isFinite(offset) && offset >= 0) url.searchParams.set("offset", String(offset));

  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "api-key": apiKey
    }
  });
  const data = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, data };
}

async function brevoGetAllContactsInList({ apiKey, listId, pageLimit }) {
  const limit = Number.isFinite(pageLimit) && pageLimit > 0 ? pageLimit : 500;
  let offset = 0;
  let expectedCount = null;
  const contacts = [];

  while (true) {
    const r = await brevoGetContactsInList({ apiKey, listId, limit, offset });
    if (!r.ok) return r;

    const pageContacts = Array.isArray(r.data?.contacts) ? r.data.contacts : [];
    if (typeof r.data?.count === "number") expectedCount = r.data.count;

    contacts.push(...pageContacts);

    if (expectedCount !== null && contacts.length >= expectedCount) break;
    if (pageContacts.length === 0) break;

    offset += pageContacts.length;
  }

  return { ok: true, status: 200, data: { count: expectedCount ?? contacts.length, contacts } };
}

function extractEmailsFromBody(body) {
  const takeEmail = (value) => {
    if (!value) return "";
    if (typeof value === "string") return value.trim();
    if (typeof value === "object") {
      const candidates = [value.email, value.Email, value.mail, value.correo];
      for (const c of candidates) {
        if (typeof c === "string" && c.trim()) return c.trim();
      }
    }
    return "";
  };

  const items =
    Array.isArray(body) ? body : Array.isArray(body?.emails) ? body.emails : Array.isArray(body?.contacts) ? body.contacts : [];

  const emails = items.map(takeEmail).filter(Boolean);
  return Array.from(new Set(emails));
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
  if (!requireCronAuthIfConfigured(req, res)) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
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
        if (lead?.data?.Nombre) attributes.NOMBRE = String(lead.data.Nombre);
        if (lead?.data?.Apellido) attributes.APELLIDOS = String(lead.data.Apellido);
        const phone = normalizePhone(lead?.data?.telefono);
        if (phone) attributes.TELEFONO = phone;
        if (phone) attributes.SMS = phone;
        if (lead?.data?.web) attributes.URL_SITIO = String(lead.data.web);
        if (lead?.data?.selecciona_un_servicio)
          attributes.SERVICIOS = String(lead.data.selecciona_un_servicio);
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

      const message = String(firstAttempt.data?.message || firstAttempt.data?.error?.message || "").toLowerCase();
      const invalidPhone = message.includes("invalid phone number");
      const withoutPhone = { ...c.attributes };
      delete withoutPhone.TELEFONO;
      delete withoutPhone.SMS;

      const fallbackAttempt = await brevoUpsertContact({
        apiKey: brevoKey,
        email: c.email,
        attributes: invalidPhone ? withoutPhone : {},
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
      const successEmails = results
        .filter((r) => typeof r.status === "number" && r.status >= 200 && r.status < 300)
        .map((r) => String(r.email || "").trim().toLowerCase())
        .filter(Boolean);

      const unique = Array.from(new Set(successEmails));
      const validFormat = unique.filter(isValidEmail);

      if (validFormat.length === 0) {
        listAdd = {
          ok: true,
          list_id: listIdNumber,
          note: "no_valid_emails_for_bulk_add",
          batches: []
        };
      } else {
        const emails = validFormat;
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
