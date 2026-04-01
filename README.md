# API Brevo Meta

API en Node.js + Express para consultar Meta Graph API (páginas, formularios Lead Ads y leads).

## Requisitos

- Node.js 18+ (recomendado)

## Configuración

Crea un archivo `.env` en la raíz:

```
PORT=3000
META_ACCESS_TOKEN=TU_TOKEN_DE_META
```

## Ejecutar

- Desarrollo (nodemon):
  - `npm run dev`
- Producción:
  - `npm start`

Si el puerto 3000 está ocupado:

```
PORT=3001 npm run dev
```

## Endpoints

Base URL (por defecto): `http://localhost:3000`

### 1) Healthcheck

**GET** `/health`

Ejemplo:

- `http://localhost:3000/health`

Respuesta:

```json
{ "ok": true }
```

---

### 2) Verificar token / Usuario actual (Meta)

**GET** `/meta/me`

Query params:

- `fields` (opcional): campos de Graph API para `/me`. Default: `id,name`

Ejemplos:

- `http://localhost:3000/meta/me`
- `http://localhost:3000/meta/me?fields=id,name`

Respuesta (ejemplo):

```json
{
  "ok": true,
  "data": { "id": "…", "name": "…" }
}
```

---

### 3) Listar formularios Lead Ads de páginas del token

**GET** `/meta/forms`

Query params:

- `page_id` (opcional): si lo envías, lista formularios solo de esa página. Si no, usa `/me/accounts` para obtener todas las páginas disponibles para el token.

Ejemplos:

- `http://localhost:3000/meta/forms`
- `http://localhost:3000/meta/forms?page_id=123456789`

Respuesta:

```json
{
  "ok": true,
  "total": 3,
  "forms": [
    {
      "id": "3270047599818919",
      "name": "Formulario X",
      "status": "ACTIVE",
      "created_time": "2024-01-01T00:00:00+0000",
      "leads_count": 10,
      "page_id": "161236013743985"
    }
  ],
  "errors": []
}
```

Notas:

- Si `errors` trae items por `page_id`, normalmente es un tema de permisos en Meta.
- Para Lead Ads suelen requerirse permisos como `leads_retrieval`, `pages_show_list` y/o `pages_manage_ads` según el caso.

---

### 4) Obtener datos de un formulario por ID

**GET** `/meta/forms/:form_id`

Params:

- `form_id`: id del formulario (leadgen form)

Query params:

- `fields` (opcional): campos del formulario. Default: `id,name,status,created_time,leads_count,locale,questions`

Ejemplos:

- `http://localhost:3000/meta/forms/3270047599818919`
- `http://localhost:3000/meta/forms/3270047599818919?fields=id,name,questions`

Respuesta:

```json
{
  "ok": true,
  "form": {
    "id": "3270047599818919",
    "name": "Formulario X"
  }
}
```

---

### 5) Obtener todos los leads de un formulario

**GET** `/meta/forms/:form_id/leads`

Params:

- `form_id`: id del formulario (leadgen form)

Query params:

- `fields` (opcional): campos del lead. Default: `id,created_time,ad_id,form_id,field_data`
- `limit` (opcional): page size que Meta usa internamente por request. La API sigue paginando hasta traer todo.

Ejemplos:

- `http://localhost:3000/meta/forms/3270047599818919/leads`
- `http://localhost:3000/meta/forms/3270047599818919/leads?fields=id,created_time,field_data`
- `http://localhost:3000/meta/forms/3270047599818919/leads?limit=100`

Respuesta:

```json
{
  "ok": true,
  "total": 2,
  "leads": [
    {
      "id": "…",
      "created_time": "…",
      "field_data": [
        { "name": "email", "values": ["correo@dominio.com"] }
      ]
    }
  ]
}
```

---

### 6) Sincronizar leads a Brevo (crear/actualizar contactos)

**GET** `/brevo/sync/forms/:form_id/leads`

Requisitos:

- `.env`: `BREVO_API_KEY=...`
- Opcional `.env`: `BREVO_LIST_ID=123`

Query params:

- `dry_run` (opcional): si es `1` o `true`, no llama a Brevo y solo muestra qué enviaría.
- `list_id` (opcional): id de lista de Brevo para agregar los contactos (override de `BREVO_LIST_ID`).
- `limit` (opcional): page size usado al consultar Meta (la API sigue paginando hasta traer todo).

Ejemplos:

- `http://localhost:3000/brevo/sync/forms/3270047599818919/leads?dry_run=1`
- `http://localhost:3000/brevo/sync/forms/3270047599818919/leads`
- `http://localhost:3000/brevo/sync/forms/3270047599818919/leads?list_id=12`

Notas:

- Se usa el correo (`data.correo`) como `email` en Brevo.
- Se intenta enviar atributos (`FIRSTNAME`, `LASTNAME`, `PHONE`, `WEB`, `SERVICIO`, `MENSAJE`). Si Brevo rechaza atributos no existentes, reintenta creando el contacto sin atributos.
- Si existe `list_id`, además de crear/actualizar el contacto también se hace un “add a lista” explícito para asegurar que queden dentro de la lista.

## Autenticación (token)

Por defecto, la API usa `META_ACCESS_TOKEN` desde `.env`.

Opcionalmente, puedes enviar el token por header:

- `Authorization: Bearer <token>`

## Troubleshooting

- `EADDRINUSE`:
  - El puerto está ocupado. Cambia `PORT` (ej. `PORT=3001`).
- Errores `(#200) Requires ... permission`:
  - Falta permiso en el token o el usuario no es admin de la página.
