const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1); // Render pone un proxy delante
const server = http.createServer(app);

/* ---------------------------------------------------------
   CORS: por defecto solo mismo origen (las páginas las sirve
   este mismo servidor). Si algún día las páginas se alojan en
   otro dominio, define ORIGENES_PERMITIDOS="https://a.com,https://b.com"
--------------------------------------------------------- */
const ORIGENES = (process.env.ORIGENES_PERMITIDOS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const opcionesSocket = {};
if (ORIGENES.length) {
  opcionesSocket.cors = { origin: ORIGENES, methods: ["GET", "POST"] };
}

const io = new Server(server, opcionesSocket);

/* ---------------------------------------------------------
   Credenciales del médico (cámbialas en Render > Environment)
     MED_USER = usuario
     MED_PASS = contraseña
--------------------------------------------------------- */
const MED_USER = process.env.MED_USER || "Luis.ortega8";
const MED_PASS = process.env.MED_PASS || "123456789";

/* ---------------------------------------------------------
   BASE DE DATOS EN EL SERVIDOR (archivo JSON)
   Aquí viven los pacientes, terapias, sesiones, signos vitales
   y eventos. Así cualquier dispositivo ve lo mismo.

   IMPORTANTE en Render: el disco normal se borra en cada
   reinicio/despliegue. Para que los datos NO se pierdan:
     1) Agrega un "Disk" en Render (montado, p. ej., en /var/data)
     2) Define la variable DATA_DIR=/var/data
--------------------------------------------------------- */
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "datos");
const DB_FILE = path.join(DATA_DIR, "base.json");

let db = { pacientes: {}, vitales: {}, eventos: {} };

function cargarDb() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (fs.existsSync(DB_FILE)) {
      const j = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
      db = {
        pacientes: j.pacientes || {},
        vitales: j.vitales || {},
        eventos: j.eventos || {}
      };
    }
    console.log("Base de datos cargada:", Object.keys(db.pacientes).length, "paciente(s) en", DB_FILE);
  } catch (e) {
    console.error("No se pudo leer la base de datos:", e.message);
  }
}

let temporizadorGuardado = null;

function escribirDbYa() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DB_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) {
    console.error("No se pudo guardar la base de datos:", e.message);
  }
}

function guardarDb() {
  if (temporizadorGuardado) return;
  temporizadorGuardado = setTimeout(() => {
    temporizadorGuardado = null;
    escribirDbYa();
  }, 800);
}

function cerrarLimpio() {
  if (temporizadorGuardado) clearTimeout(temporizadorGuardado);
  escribirDbYa();
  process.exit(0);
}
process.on("SIGTERM", cerrarLimpio);
process.on("SIGINT", cerrarLimpio);

cargarDb();

/* ---------------------------------------------------------
   Archivos que NO deben poder descargarse desde el navegador
--------------------------------------------------------- */
const BLOQUEADOS = [
  /^\/server\.js$/i,
  /^\/package(-lock)?\.json$/i,
  /^\/node_modules(\/|$)/i,
  /^\/datos(\/|$)/i,
  /^\/\./,
  /\.blend1?$/i
];

app.use((req, res, next) => {
  let ruta = req.path;
  try {
    ruta = decodeURIComponent(req.path);
  } catch (e) {
    return res.status(400).end();
  }
  if (BLOQUEADOS.some((r) => r.test(ruta))) {
    return res.status(404).end();
  }
  next();
});

app.use(express.json({ limit: "5mb" }));
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/salud", (req, res) => res.json({ ok: true }));

/* ---------------------------------------------------------
   Servidores ICE (STUN / TURN) para WebRTC.
     TURN_URL  = turn:servidor:3478,turns:servidor:443?transport=tcp
     TURN_USER = usuario
     TURN_PASS = clave
--------------------------------------------------------- */
app.get("/api/ice", (req, res) => {
  const iceServers = [{ urls: "stun:stun.l.google.com:19302" }];

  if (process.env.TURN_URL) {
    iceServers.push({
      urls: process.env.TURN_URL.split(",").map((s) => s.trim()).filter(Boolean),
      username: process.env.TURN_USER || "",
      credential: process.env.TURN_PASS || ""
    });
  }

  res.set("Cache-Control", "no-store");
  res.json({ iceServers });
});

/* ---------------------------------------------------------
   Utilidades
--------------------------------------------------------- */
const tokens = new Map(); // token -> expira (ms)
const DURACION_TOKEN = 12 * 60 * 60 * 1000;

function iguales(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function tokenValido(t) {
  if (!t) return false;
  const exp = tokens.get(t);
  if (!exp) return false;
  if (exp < Date.now()) {
    tokens.delete(t);
    return false;
  }
  return true;
}

// Límite simple de intentos por IP
const intentos = new Map(); // clave -> { n, desde }
function limitar(clave, max, ventanaMs) {
  const ahora = Date.now();
  const r = intentos.get(clave);
  if (!r || ahora - r.desde > ventanaMs) {
    intentos.set(clave, { n: 1, desde: ahora });
    return false;
  }
  r.n++;
  return r.n > max;
}
setInterval(() => {
  const ahora = Date.now();
  for (const [k, r] of intentos.entries()) {
    if (ahora - r.desde > 3600000) intentos.delete(k);
  }
  for (const [t, exp] of tokens.entries()) {
    if (exp < ahora) tokens.delete(t);
  }
}, 600000);

function requiereMedico(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!tokenValido(t)) return res.status(401).json({ error: "No autorizado" });
  next();
}

function mezclarPorClave(a, b, claveFn) {
  const mapa = new Map();
  (Array.isArray(a) ? a : []).forEach((x) => mapa.set(claveFn(x), x));
  (Array.isArray(b) ? b : []).forEach((x) => {
    const k = claveFn(x);
    if (!mapa.has(k)) mapa.set(k, x);
  });
  return [...mapa.values()];
}

const claveSesion = (s) => String((s && s.fecha) || JSON.stringify(s));
const claveApunte = (a) => String((a && a.fecha) || "") + "|" + String((a && a.texto) || "");

function fichaValida(f, cedula) {
  return (
    f &&
    typeof f === "object" &&
    f.paciente &&
    String(f.paciente.documento || "").trim() === String(cedula)
  );
}

// Une la ficha que manda el médico con lo que el servidor ya tiene
function guardarFicha(cedula, entrante) {
  const actual = db.pacientes[cedula] || {};
  const ficha = Object.assign({}, entrante);
  ficha.sesionesHistorial = mezclarPorClave(actual.sesionesHistorial, entrante.sesionesHistorial, claveSesion);
  ficha.apuntesMedico = mezclarPorClave(entrante.apuntesMedico, actual.apuntesMedico, claveApunte);
  if (!ficha.terapias) ficha.terapias = actual.terapias || {};
  db.pacientes[cedula] = ficha;
  guardarDb();
  return ficha;
}

function numeroEnRango(v, min, max) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return n;
}

function textoCorto(v, max = 40) {
  if (v === null || v === undefined) return "";
  return String(v).slice(0, max);
}

function agregarEvento(cedula, ev) {
  if (!db.eventos[cedula]) db.eventos[cedula] = [];
  db.eventos[cedula].push(Object.assign({ t: Date.now() }, ev));
  if (db.eventos[cedula].length > 500) db.eventos[cedula].splice(0, db.eventos[cedula].length - 500);
  guardarDb();
}

/* ---------------------------------------------------------
   API del MÉDICO (requiere iniciar sesión)
--------------------------------------------------------- */
app.post("/api/medico/login", (req, res) => {
  if (limitar("med:" + req.ip, 8, 10 * 60 * 1000)) {
    return res.status(429).json({ error: "Demasiados intentos. Espera unos minutos." });
  }
  const { user, pin } = req.body || {};
  if (iguales(user || "", MED_USER) && iguales(pin || "", MED_PASS)) {
    const token = crypto.randomBytes(24).toString("hex");
    tokens.set(token, Date.now() + DURACION_TOKEN);
    return res.json({ token });
  }
  res.status(401).json({ error: "Credenciales inválidas" });
});

app.get("/api/pacientes", requiereMedico, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(Object.values(db.pacientes));
});

app.put("/api/pacientes/:cedula", requiereMedico, (req, res) => {
  const cedula = String(req.params.cedula).trim();
  if (!fichaValida(req.body, cedula)) return res.status(400).json({ error: "Ficha inválida" });
  const ficha = guardarFicha(cedula, req.body);
  res.json(ficha);
});

// Migración: sube pacientes que estaban solo en el navegador del médico
app.post("/api/pacientes/importar", requiereMedico, (req, res) => {
  const lista = Array.isArray(req.body) ? req.body : [];
  let nuevos = 0;
  lista.forEach((f) => {
    const cedula = f && f.paciente ? String(f.paciente.documento || "").trim() : "";
    if (!cedula || !fichaValida(f, cedula)) return;
    if (!db.pacientes[cedula]) nuevos++;
    const existente = db.pacientes[cedula];
    guardarFicha(
      cedula,
      existente
        ? Object.assign({}, existente, {
            sesionesHistorial: f.sesionesHistorial,
            apuntesMedico: f.apuntesMedico
          })
        : f
    );
  });
  res.json({ ok: true, nuevos });
});

app.delete("/api/pacientes/:cedula", requiereMedico, (req, res) => {
  const cedula = String(req.params.cedula).trim();
  delete db.pacientes[cedula];
  delete db.vitales[cedula];
  delete db.eventos[cedula];
  guardarDb();
  res.json({ ok: true });
});

app.get("/api/pacientes/:cedula/historial", requiereMedico, (req, res) => {
  const cedula = String(req.params.cedula).trim();
  res.set("Cache-Control", "no-store");
  res.json({
    vitales: db.vitales[cedula] || [],
    eventos: db.eventos[cedula] || []
  });
});

/* ---------------------------------------------------------
   API del PACIENTE (entra con su cédula)
--------------------------------------------------------- */
app.post("/api/paciente/login", (req, res) => {
  if (limitar("pac:" + req.ip, 40, 10 * 60 * 1000)) {
    return res.status(429).json({ error: "Demasiados intentos. Espera unos minutos." });
  }
  const cedula = String((req.body && req.body.cedula) || "").trim();
  const ficha = cedula ? db.pacientes[cedula] : null;
  if (!ficha) return res.status(404).json({ error: "No encontrado" });

  // El paciente no recibe los apuntes privados del médico
  const copia = Object.assign({}, ficha);
  delete copia.apuntesMedico;
  res.set("Cache-Control", "no-store");
  res.json(copia);
});

/* ---------------------------------------------------------
   Estado en memoria (conexiones en vivo)
--------------------------------------------------------- */
const pacientes = new Map(); // cedula -> { socketId, nombre }
const llamadas = new Map(); //  cedula -> socketId del médico que llama

function listaEnLinea() {
  return [...pacientes.entries()].map(([cedula, p]) => ({
    cedula,
    nombre: p.nombre,
    conectado: true
  }));
}

function ultimosVitales() {
  const out = {};
  Object.keys(db.vitales).forEach((ced) => {
    const arr = db.vitales[ced];
    if (arr && arr.length) out[ced] = arr[arr.length - 1];
  });
  return out;
}

function socketVivo(id) {
  return !!id && io.sockets.sockets.has(id);
}

io.on("connection", (socket) => {
  console.log("Conectado:", socket.id);

  /* ---------- Registro ---------- */

  socket.on("patient:join", (data = {}) => {
    const cedula = String(data.cedula || "").trim();
    if (!cedula) return;

    const nombre = data.nombre || "Paciente";

    socket.data.cedula = cedula;
    socket.data.tipo = "paciente";
    socket.join(`paciente:${cedula}`);

    pacientes.set(cedula, { socketId: socket.id, nombre });

    io.to("medicos").emit("server:patient-online", {
      cedula,
      nombre,
      conectado: true
    });

    console.log("Paciente conectado:", cedula);
  });

  socket.on("doctor:join", () => {
    // Solo entra un médico con sesión válida
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!tokenValido(token)) {
      socket.emit("server:auth-error");
      return;
    }

    socket.data.tipo = "medico";
    socket.join("medicos");

    socket.emit("server:patients-online", listaEnLinea());
    socket.emit("server:ultimos-vitales", ultimosVitales());

    console.log("Médico conectado:", socket.id);
  });

  /* ---------- Paciente -> todos los médicos (datos en vivo) ---------- */

  const eventosHaciaMedicos = [
    "patient:state",
    "patient:movement",
    "patient:repetition"
  ];

  eventosHaciaMedicos.forEach((evento) => {
    socket.on(evento, (data = {}) => {
      if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;
      io.to("medicos").emit(evento, { ...data, cedula: socket.data.cedula });
    });
  });

  // SOS: se reenvía y además queda en el registro del paciente
  socket.on("patient:sos", (data = {}) => {
    if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;
    const cedula = socket.data.cedula;
    io.to("medicos").emit("patient:sos", { ...data, cedula });
    if (db.pacientes[cedula]) agregarEvento(cedula, { tipo: "SOS", detalle: "El paciente solicitó ayuda médica" });
  });

  // Signos vitales: se guardan en el servidor y se reenvían al médico
  socket.on("patient:vitals", (data = {}) => {
    if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;
    const cedula = socket.data.cedula;
    if (!db.pacientes[cedula]) return;

    const ang = data.angulos || {};
    const tCliente = Number(data.t);
    const ahora = Date.now();
    const registro = {
      t: Number.isFinite(tCliente) && tCliente <= ahora + 60000 && tCliente > ahora - 7 * 86400000 ? tCliente : ahora,
      pulso: numeroEnRango(data.pulso, 20, 250),
      respiracion: numeroEnRango(data.respiracion, 3, 80),
      saturacion: numeroEnRango(data.saturacion, 40, 100),
      temperatura: numeroEnRango(data.temperatura, 30, 45),
      hombro: numeroEnRango(ang.hombro, -360, 360),
      codo: numeroEnRango(ang.codo, -360, 360),
      cadera: numeroEnRango(ang.cadera, -360, 360),
      estado: textoCorto(data.estado),
      dia: numeroEnRango(data.dia, 0, 1000),
      repeticiones: numeroEnRango(data.repeticiones, 0, 100000),
      origen: data.origen === "terapia" ? "terapia" : "sensor"
    };

    const hayDato =
      registro.pulso !== null ||
      registro.respiracion !== null ||
      registro.saturacion !== null ||
      registro.temperatura !== null ||
      registro.hombro !== null ||
      registro.codo !== null ||
      registro.cadera !== null;
    if (!hayDato) return;

    if (!db.vitales[cedula]) db.vitales[cedula] = [];
    db.vitales[cedula].push(registro);
    if (db.vitales[cedula].length > 20000) {
      db.vitales[cedula].splice(0, db.vitales[cedula].length - 20000);
    }
    guardarDb();

    io.to("medicos").emit("patient:vitals", { ...registro, cedula });
  });

  // Sesión terminada: se guarda en el servidor y se avisa al médico
  socket.on("patient:session-completed", (data = {}) => {
    if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;
    const cedula = socket.data.cedula;
    const sesion = { ...data, cedula };

    if (db.pacientes[cedula]) {
      const ficha = db.pacientes[cedula];
      if (!Array.isArray(ficha.sesionesHistorial)) ficha.sesionesHistorial = [];
      const tam = JSON.stringify(sesion).length;
      if (tam < 60000 && !ficha.sesionesHistorial.some((s) => s.fecha === sesion.fecha)) {
        ficha.sesionesHistorial.push(sesion);
        guardarDb();
      }
    }

    io.to("medicos").emit("patient:session-completed", sesion);
  });

  /* ---------- Paciente -> el médico de SU llamada ---------- */

  const eventosLlamadaHaciaMedico = [
    "patient:call-accepted",
    "patient:call-rejected",
    "patient:answer",
    "patient:ice-candidate",
    "patient:hangup"
  ];

  eventosLlamadaHaciaMedico.forEach((evento) => {
    socket.on(evento, (data = {}) => {
      if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;

      const cedula = socket.data.cedula;
      const medicoId = llamadas.get(cedula);

      if (!medicoId || !socketVivo(medicoId)) return;

      io.to(medicoId).emit(evento, { ...data, cedula });

      if (evento === "patient:hangup" || evento === "patient:call-rejected") {
        llamadas.delete(cedula);
      }
    });
  });

  /* ---------- Médico -> paciente ---------- */

  socket.on("doctor:call-request", (data = {}) => {
    if (socket.data.tipo !== "medico") return;

    const cedula = String(data.cedula || "").trim();
    if (!cedula) return;

    if (!pacientes.has(cedula)) {
      socket.emit("server:patient-offline", { cedula });
      return;
    }

    const otro = llamadas.get(cedula);
    if (otro && otro !== socket.id && socketVivo(otro)) {
      socket.emit("server:patient-busy", { cedula });
      return;
    }

    llamadas.set(cedula, socket.id);
    io.to(`paciente:${cedula}`).emit("doctor:call-request", { cedula });
  });

  ["doctor:offer", "doctor:ice-candidate", "doctor:hangup", "doctor:command"].forEach((evento) => {
    socket.on(evento, (data = {}) => {
      if (socket.data.tipo !== "medico") return;

      const cedula = String(data.cedula || "").trim();
      if (!cedula) return;

      if (llamadas.get(cedula) !== socket.id) return;

      io.to(`paciente:${cedula}`).emit(evento, data);

      if (evento === "doctor:hangup") {
        llamadas.delete(cedula);
      }
    });
  });

  // El médico habilita, bloquea o programa las terapias del paciente
  socket.on("doctor:terapias", (data = {}) => {
    if (socket.data.tipo !== "medico") return;

    const cedula = String(data.cedula || "").trim();
    if (!cedula) return;

    if (db.pacientes[cedula] && data.terapias && typeof data.terapias === "object") {
      db.pacientes[cedula].terapias = data.terapias;
      guardarDb();
    }

    io.to(`paciente:${cedula}`).emit("doctor:terapias", { cedula, terapias: data.terapias });
  });

  socket.on("doctor:alert-acknowledged", (data = {}) => {
    if (socket.data.tipo !== "medico") return;

    const cedula = String(data.cedula || "").trim();
    if (!cedula) return;

    if (db.pacientes[cedula]) agregarEvento(cedula, { tipo: "SOS atendido", detalle: "El médico confirmó la solicitud" });

    io.to(`paciente:${cedula}`).emit("doctor:alert-acknowledged", data);
  });

  /* ---------- Desconexión ---------- */

  socket.on("disconnect", () => {
    const cedula = socket.data.cedula;

    if (socket.data.tipo === "paciente" && cedula) {
      const registro = pacientes.get(cedula);

      if (registro && registro.socketId === socket.id) {
        pacientes.delete(cedula);

        io.to("medicos").emit("server:patient-online", {
          cedula,
          conectado: false
        });

        const medicoId = llamadas.get(cedula);
        if (medicoId && socketVivo(medicoId)) {
          io.to(medicoId).emit("patient:hangup", { cedula });
        }
        llamadas.delete(cedula);
      }
    }

    if (socket.data.tipo === "medico") {
      for (const [ced, medicoId] of llamadas.entries()) {
        if (medicoId === socket.id) {
          io.to(`paciente:${ced}`).emit("doctor:hangup", { cedula: ced });
          llamadas.delete(ced);
        }
      }
    }

    console.log("Desconectado:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor activo en http://localhost:${PORT}`);
});
