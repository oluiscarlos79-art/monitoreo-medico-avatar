const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
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

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* ---------------------------------------------------------
   Servidores ICE (STUN / TURN) para WebRTC.
   Los dos portales lo piden aquí, así no hay claves en el HTML.
   TURN se activa con variables de entorno:
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
   Estado en memoria
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

    // Solo los médicos se enteran de quién está en línea
    io.to("medicos").emit("server:patient-online", {
      cedula,
      nombre,
      conectado: true
    });

    console.log("Paciente conectado:", cedula);
  });

  socket.on("doctor:join", () => {
    socket.data.tipo = "medico";
    socket.join("medicos");

    // Al entrar, el médico recibe la lista de pacientes ya conectados
    socket.emit("server:patients-online", listaEnLinea());

    console.log("Médico conectado:", socket.id);
  });

  /* ---------- Paciente -> todos los médicos (datos en vivo) ---------- */

  const eventosHaciaMedicos = [
    "patient:sos",
    "patient:state",
    "patient:movement",
    "patient:repetition",
    "patient:session-completed"
  ];

  eventosHaciaMedicos.forEach((evento) => {
    socket.on(evento, (data = {}) => {
      if (socket.data.tipo !== "paciente" || !socket.data.cedula) return;

      // La cédula la pone el servidor, no el cliente
      io.to("medicos").emit(evento, { ...data, cedula: socket.data.cedula });
    });
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

      // Solo el médico que inició la llamada puede señalizar en ella
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

    io.to(`paciente:${cedula}`).emit("doctor:terapias", { cedula, terapias: data.terapias });
  });

  socket.on("doctor:alert-acknowledged", (data = {}) => {
    if (socket.data.tipo !== "medico") return;

    const cedula = String(data.cedula || "").trim();
    if (!cedula) return;

    io.to(`paciente:${cedula}`).emit("doctor:alert-acknowledged", data);
  });

  /* ---------- Desconexión ---------- */

  socket.on("disconnect", () => {
    const cedula = socket.data.cedula;

    if (socket.data.tipo === "paciente" && cedula) {
      const registro = pacientes.get(cedula);

      // Solo se borra si este socket sigue siendo el vigente del paciente
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