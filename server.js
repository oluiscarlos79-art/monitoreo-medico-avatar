
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

const pacientes = new Map();

io.on("connection", (socket) => {
  console.log("Conectado:", socket.id);

  socket.on("patient:join", (data = {}) => {
    const cedula = String(data.cedula || "").trim();

    if (!cedula) return;

    socket.data.cedula = cedula;
    socket.data.tipo = "paciente";
    socket.join(`paciente:${cedula}`);

    pacientes.set(cedula, {
      socketId: socket.id,
      nombre: data.nombre || "Paciente",
      conectado: true
    });

    io.emit("server:patient-online", {
      cedula,
      nombre: data.nombre || "Paciente",
      conectado: true
    });

    console.log("Paciente conectado:", cedula);
  });

  socket.on("doctor:join", () => {
    socket.data.tipo = "medico";
    socket.join("medicos");
    console.log("Médico conectado:", socket.id);
  });

  const eventosHaciaMedicos = [
    "patient:call-request",
    "patient:call-accepted",
    "patient:answer",
    "patient:ice-candidate",
    "patient:hangup",
    "patient:sos",
    "patient:movement",
    "patient:repetition",
    "patient:session-completed",
    "patient:call-rejected"
  ];

  eventosHaciaMedicos.forEach((evento) => {
    socket.on(evento, (data = {}) => {
      io.to("medicos").emit(evento, {
        ...data,
        cedula: data.cedula || socket.data.cedula
      });
    });
  });

  const eventosHaciaPaciente = [
    "doctor:call-request",
    "doctor:offer",
    "doctor:ice-candidate",
    "doctor:hangup",
    "doctor:alert-acknowledged"
  ];

  eventosHaciaPaciente.forEach((evento) => {
    socket.on(evento, (data = {}) => {
      const cedula = String(data.cedula || "").trim();

      if (!cedula) return;

      io.to(`paciente:${cedula}`).emit(evento, data);
    });
  });

  socket.on("disconnect", () => {
    const cedula = socket.data.cedula;

    if (cedula && pacientes.has(cedula)) {
      pacientes.delete(cedula);

      io.emit("server:patient-online", {
        cedula,
        conectado: false
      });
    }

    console.log("Desconectado:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor activo en http://localhost:${PORT}`);
});
