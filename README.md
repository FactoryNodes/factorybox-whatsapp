# factorybox-whatsapp

Proceso de WhatsApp de la **Factory Box** de [FactoryNodes](https://www.factorynodes.com): manda los avisos de alarmas de la
planta por WhatsApp Web, con [Baileys](https://github.com/WhiskeySockets/Baileys).

Licencia: **MIT** ([LICENSE](LICENSE)). Copyright (c) 2026 Vicente Zaragoza Arnau. Hasta el 12 de noviembre de 2026 se publicó con la
GPL 3.0 o posterior, porque llevaba libsignal-node; desde entonces el cifrado es
[signal-protocol-mit](signal-protocol-mit), del mismo autor y también MIT.

## Qué es y qué no es

Es un programa de Node.js independiente. El visor de la Factory Box (software propietario, no incluido aquí) lo lanza
como un **proceso aparte** y se comunica con él solo por la entrada y la salida estándar, con un mensaje JSON por línea.
Este repositorio es el código fuente completo de ese proceso, tal como va instalado en la caja
(`/opt/factorybox/app/whatsapp/`), y el de su librería de cifrado (`signal-protocol-mit/`).

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

Las versiones exactas están en [package-lock.json](package-lock.json).

**El cifrado.** Baileys pide el paquete `libsignal` (libsignal-node, GPL-3.0) y `npm ci` lo baja. En la Factory Box **no va**: al
hacer el firmware se quita y en su sitio (`node_modules/libsignal`) se pone [signal-protocol-mit](signal-protocol-mit), que
ofrece la parte que Baileys usa (X3DH y Double Ratchet, escritos desde las especificaciones públicas de Signal; ver su
`PROVENANCE.md`). Así lo que lleva la caja no tiene nada GPL. Quien instale las dependencias sin hacer ese cambio tendrá
libsignal-node y, con ella, las condiciones de la GPL al repartirlo.

La que se distribuye con una licencia que pide dar el código fuente:

| Componente | Versión | Licencia | Código fuente |
|---|---|---|---|
| libvips (binarios de `@img/sharp-libvips-linux-x64`) | 1.3.2 | LGPL-3.0-or-later | https://github.com/lovell/sharp-libvips |

El resto (Baileys, pino, protobufjs, ws, axios, sharp…) tienen licencias MIT, BSD, ISC, 0BSD o Apache 2.0; su texto va en
cada paquete de `node_modules`. En la caja se usa además Node.js 22 para Linux x64 (MIT, https://nodejs.org).

Para instalar las dependencias igual que en la caja:

```
npm ci --omit=dev --os=linux --cpu=x64 --libc=glibc
(cd signal-protocol-mit && npm ci --omit=dev)
rm -rf node_modules/libsignal
mkdir node_modules/libsignal
cp -r signal-protocol-mit/index.js signal-protocol-mit/src signal-protocol-mit/package.json signal-protocol-mit/LICENSE       signal-protocol-mit/node_modules node_modules/libsignal/
```
