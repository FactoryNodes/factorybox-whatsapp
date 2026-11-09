# factorybox-whatsapp

Proceso de WhatsApp de la **Factory Box** de [FactoryNodes](https://www.factorynodes.com): manda los avisos de alarmas de la
planta por WhatsApp Web, con [Baileys](https://github.com/WhiskeySockets/Baileys).

Licencia: **GNU GPL 3.0 o posterior** ([LICENSE](LICENSE)). Copyright (C) 2026 Vicente Zaragoza Arnau.

## Qué es y qué no es

Es un programa de Node.js independiente. El visor de la Factory Box (software propietario, no incluido aquí) lo lanza
como un **proceso aparte** y se comunica con él solo por la entrada y la salida estándar, con un mensaje JSON por línea.
Este repositorio es el código fuente completo de ese proceso, tal como va instalado en la caja
(`/opt/factorybox/app/whatsapp/`).

## Cómo funciona

```
node index.js            # datos en ./data, o en la carpeta de FACTORYBOX_WHATSAPP_DATA
```

Comandos (stdin, un JSON por línea):

| Comando | Qué hace |
|---|---|
| `{"cmd":"send","envioId":"…","destino":{"idExterno":"34600111222@s.whatsapp.net"},"texto":"…"}` | Manda un texto a un número o a un grupo (`…@g.us`) |
| `{"cmd":"listarGrupos"}` | Lista los grupos de la cuenta vinculada |
| `{"cmd":"desvincular"}` | Cierra la sesión en WhatsApp y saca un QR nuevo |
| `{"cmd":"shutdown"}` | Termina |

Eventos (stdout, un JSON por línea):

| Evento | Cuándo |
|---|---|
| `{"evt":"conexion","estado":"requiereReautenticacion","datosReautenticacion":"<QR>"}` | Hay que escanear el QR (WhatsApp ▸ Dispositivos vinculados) |
| `{"evt":"conexion","estado":"conectado","identidadConectada":"…"}` | Vinculado y conectado |
| `{"evt":"conexion","estado":"bloqueado"}` / `"desconectado"` | Sesión cerrada / reconectando |
| `{"evt":"envio","envioId":"…","estado":"enviadoOk"}` / `"error"` | Resultado de un envío |
| `{"evt":"grupos","grupos":[{"jid":"…","nombre":"…"}]}` | Respuesta a `listarGrupos` |

El diagnóstico va por stderr.

## Dependencias y su código fuente

Las versiones exactas están en [package-lock.json](package-lock.json). Las que se distribuyen con licencias que piden dar
el código fuente:

| Componente | Versión | Licencia | Código fuente |
|---|---|---|---|
| libsignal-node | 6.0.0 (commit `bcea72df9ec34d9d9140ab30619cf479c7c144c7`) | GPL-3.0 | https://github.com/whiskeysockets/libsignal-node/tree/bcea72df9ec34d9d9140ab30619cf479c7c144c7 |
| libvips (binarios de `@img/sharp-libvips-linux-x64`) | 1.3.2 | LGPL-3.0-or-later | https://github.com/lovell/sharp-libvips |

El resto (Baileys, pino, protobufjs, ws, axios, sharp…) tienen licencias MIT, BSD, ISC, 0BSD o Apache 2.0; su texto va en
cada paquete de `node_modules`. En la caja se usa además Node.js 22 para Linux x64 (MIT, https://nodejs.org).

Para instalar las dependencias igual que en la caja:

```
npm ci --omit=dev --os=linux --cpu=x64 --libc=glibc
```
