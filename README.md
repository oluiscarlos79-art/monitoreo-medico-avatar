# monitoreo-medico-avatar

Plataforma web de tele-rehabilitación UAC: portal del paciente (`index.html`, avatar 3D, voz, cámara y sensores) y portal médico (`medico.html`, historial clínico, videollamada y datos en tiempo real).

## Archivos

- `server.js`: Express + Socket.IO + API (`/api/medico/*`, `/api/pacientes`, `/api/ice`).
- `index.html`: portal del paciente. `medico.html`: portal médico. `datos-crudos.html`: ventana separada de datos entrantes.
- `uac-theme.css`: colores y tipografía compartidos.
- Deben estar en la misma carpeta: `escudo_uac.png` y `terapia.1.fbx`.

## Ejecutar en local

```
npm install
npm start
```

Abre http://localhost:3000 (paciente) y http://localhost:3000/medico.html (médico).

## Variables de entorno

Mira `.env.example`. Las principales: `SMTP_USER` y `SMTP_PASS` (correos de registro y recuperación), `MED_USER` y `MED_PASS` (administrador opcional), `REGISTRO_CODIGO` (código de invitación opcional) y `TURN_*` (videollamadas entre redes distintas).
