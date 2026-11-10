// factorybox-whatsapp — proceso de WhatsApp de la Factory Box (FactoryNodes).
// Copyright (C) 2026 Vicente Zaragoza Arnau
//
// Este programa es software libre: puedes redistribuirlo y/o modificarlo según los términos de la GNU General Public
// License publicada por la Free Software Foundation, versión 3 o (a tu elección) cualquier versión posterior. Se
// distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Ver LICENSE.
//
// Manda los avisos de alarmas de la Factory Box por WhatsApp Web (Baileys). El visor de la caja lo lanza como un proceso
// aparte y le habla por stdin/stdout, un JSON por línea (NDJSON): comandos send, listarGrupos, desvincular y shutdown;
// eventos conexion (con el QR de vinculación), envio y grupos. Los datos (sesión y mensajes enviados) van a la carpeta de
// FACTORYBOX_WHATSAPP_DATA. Sale del sidecar de IrisFlow, del mismo autor, sin la parte de recibir mensajes.
//
// Original:
// Proceso auxiliar Node.js para IrisCore/Iris.Canales.WhatsAppBaileys.
//
// Habla WhatsApp Web (protocolo multi-dispositivo) vía Baileys y expone un
// canal de comandos/eventos por stdin/stdout, un objeto JSON por línea
// (NDJSON) en cada sentido. Nunca usa console.log/console.error para nada
// que no sea diagnóstico — stdout es el canal de eventos y cualquier log
// suelto ahí rompería el parseo NDJSON del lado C#; los logs de diagnóstico
// van a stderr.
//
// Ver Iris.Canales.WhatsAppBaileys.Why.md y ARQUITECTURA.md ("Eventos de canal en
// tres familias") para el porqué de la forma de estos mensajes.

import makeWASocket, {
    useMultiFileAuthState,
    fetchLatestBaileysVersion,
    makeCacheableSignalKeyStore,
    DisconnectReason,
    jidDecode,
} from '@whiskeysockets/baileys';
import { pino } from 'pino';
import { createInterface } from 'node:readline';
import { mkdirSync, readdirSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const CARPETA_DATOS = process.env.FACTORYBOX_WHATSAPP_DATA || join(dirname(fileURLToPath(import.meta.url)), 'data');
const CARPETA_AUTH = join(CARPETA_DATOS, 'auth');
mkdirSync(CARPETA_AUTH, { recursive: true });

// Almacén en disco de los mensajes que HEMOS enviado, indexado por `key.id`.
// Baileys lo necesita como `getMessage`: cuando el dispositivo del
// destinatario no puede descifrar un mensaje pide un reintento y Baileys
// tiene que recuperar el contenido original para volver a cifrarlo. Sin esto
// el mensaje se queda en "Esperando este mensaje..." y la sesión con ese
// dispositivo se desincroniza (ver .ApiNotes.md, issue Baileys #2115). El
// almacén en memoria de la librería no vale: no sobrevive a un reinicio del
// proceso, y los reintentos pueden llegar minutos u horas después.
const CARPETA_MSGSTORE = join(CARPETA_DATOS, 'msgstore');
mkdirSync(CARPETA_MSGSTORE, { recursive: true });

// Un reintento puede tardar; unos días de margen. El tope de ficheros es una
// red de seguridad por si la poda por edad no llega a correr.
const MSGSTORE_TTL_MS = 3 * 24 * 60 * 60 * 1000;
const MSGSTORE_MAX_FICHEROS = 5000;
const MSGSTORE_PODA_CADA_MS = 6 * 60 * 60 * 1000;

// Silencioso a propósito: el logger por defecto de Baileys escribe en
// stdout, y ese canal está reservado para nuestros eventos NDJSON.
const logger = pino({ level: 'silent' });

// El socket activo — cambia en cada reconexión (ver conectar()), así que
// los manejadores de comando siempre deben leer esta variable, nunca
// capturar un socket concreto en un closure.
let sock = null;

// El almacén de claves CON caché que usa el socket (cambia en cada reconexión, como `sock`). Para borrar sesiones hay que ir por él:
// `makeCacheableSignalKeyStore` guarda las sesiones 5 minutos, y escribir en `state.keys` (lo de antes del 2026-11-01) o borrar el
// fichero dejaba la sesión rota en la caché (visto leyendo Baileys 6.7.24 y 7.0.0-rc14).
let almacenClaves = null;

// --- Alarma de sesión desincronizada por contacto ---------------------
//
// Cuando el destinatario no puede descifrar un mensaje, Baileys llama a
// `getMessage` para recuperarlo y reintentar. Un reintento suelto es
// normal (issue #2115, ver arriba); pero si el MISMO mensaje pide reintento
// varias veces, la sesión Signal con ese contacto está de verdad atascada
// (el destinatario ve en su WhatsApp el aviso de "retraso en la recepción
// de mensajes" y luego una ráfaga de mensajes duplicados cuando por fin se
// resincroniza). Contador por `key.id` (no por contacto: cada mensaje tiene
// su propio ciclo de reintentos) — sin tope explícito de tamaño porque cada
// entrada es efímera (se borra al primer intento con éxito o, como mucho,
// se acumula un puñado mientras dura la sesión).
const reintentosPorMensaje = new Map();
const UMBRAL_REINTENTOS_SOSPECHOSO = 2;

// Contactos con una alarma activa ahora mismo — para no repetir el aviso
// mientras siga sin resolverse y para saber, cuando se les vuelve a
// escribir con éxito, que hay que emitir "resuelta" (ver manejarComando 'send').
const alarmasActivas = new Set();

// El usuario de una sesión guardada: `session-34600111222.0.json` → `34600111222`; en la 7.x, `<lid>_1.<dispositivo>` → `<lid>`.
function usuarioDeSesion(id) {
    return id.split('.')[0].split('_')[0];
}

// Borra las sesiones Signal de estas personas en TODOS sus dispositivos (el fallo puede venir del móvil, de WhatsApp Web…), sin tocar
// la vinculación: no hace falta QR y Baileys las rehace en el siguiente envío. Por `almacenClaves` (ver arriba). En la 7.x la sesión
// de un número suele estar bajo su `@lid`. Devuelve cuántas ha borrado. (2026-11-01.)
async function borrarSesionesDe(jids) {
    if (!almacenClaves) {
        return 0;
    }

    const usuarios = new Set();
    for (const jid of jids) {
        const usuario = jidDecode(jid)?.user;
        if (usuario) {
            usuarios.add(usuario);
        }
        try {
            const lid = await sock?.signalRepository?.lidMapping?.getLIDForPN?.(jid);
            const usuarioLid = lid ? jidDecode(lid)?.user : null;
            if (usuarioLid) {
                usuarios.add(usuarioLid);
            }
        } catch {
            // Sin correspondencia conocida: se borra lo que se sepa del número.
        }
    }

    const sesiones = {};
    for (const nombre of readdirSync(CARPETA_AUTH)) {
        const coincidencia = /^session-(.+)\.json$/.exec(nombre);
        if (coincidencia && usuarios.has(usuarioDeSesion(coincidencia[1]))) {
            sesiones[coincidencia[1]] = null;
        }
    }

    await almacenClaves.set({ session: sesiones });
    // Qué dispositivos (no solo cuántos): para seguir un «No open session» en el registro (2026-11-01)
    logDiagnostico(`Sesiones Signal borradas: ${Object.keys(sesiones).join(', ') || '(ninguna)'}.`);
    return Object.keys(sesiones).length;
}

// Autoarreglo de mejor esfuerzo tras reintentos repetidos de un contacto: sus sesiones, en todos sus dispositivos.
async function borrarSesionContacto(remoteJid) {
    try {
        const borradas = await borrarSesionesDe([remoteJid]);
        logDiagnostico(`Autoarreglo: ${borradas} sesiones Signal de ${remoteJid} borradas tras reintentos repetidos.`);
    } catch (error) {
        logDiagnostico(`No se pudo borrar la sesión de ${remoteJid}:`, error);
    }
}

// --- Reenviar el mensaje atascado tras resincronizar (2026-11-10) -----
//
// Autor (FactoryNodes, 2026-11-10): tras un fallo de sincronización la sesión se arreglaba sola y el SIGUIENTE aviso llegaba bien, pero
// el que se atascó («Esperando este mensaje…») no llegaba. Cuando un mensaje cruza el umbral de reintentos, después del autoarreglo se
// manda otra vez como mensaje NUEVO (cifrado con la sesión rehecha), con «↻ » delante (sin idioma) y una sola vez por mensaje. Si el
// móvil acaba descifrando también el original, llega dos veces: para un aviso de alarma, mejor dos que ninguno. Solo texto (lo que
// mandan los avisos); un adjunto no se reenvía.
const REENVIO_ESPERA_MS = 5000;
const REENVIO_PREFIJO = '↻ ';
const reenviados = new Set();

// El texto de un mensaje guardado (proto de Baileys): `conversation` o `extendedTextMessage.text`.
function textoDeMensaje(message) {
    const texto = message?.conversation ?? message?.extendedTextMessage?.text;
    return typeof texto === 'string' && texto.length > 0 ? texto : null;
}

function programarReenvio(key) {
    if (!key?.id || reenviados.has(key.id) || !key.remoteJid) {
        return;
    }
    const texto = textoDeMensaje(obtenerMensajeEnviado(key.id));
    if (texto === null) {
        logDiagnostico(`Reenvío: ${key.id} no es un texto, no se reenvía.`);
        return;
    }
    reenviados.add(key.id);
    // Con margen para que el autoarreglo termine y el móvil deje de pedir el original
    setTimeout(async () => {
        const jid = key.remoteJid;
        const contenido = texto.startsWith(REENVIO_PREFIJO) ? texto : REENVIO_PREFIJO + texto;
        try {
            if (!sock) {
                throw new Error('sin conexión');
            }
            const info = await enviarConUnReintento(jid, { text: contenido });
            guardarMensajeEnviado(info?.key?.id, info?.message);
            logDiagnostico(`Reenvío: ${key.id} mandado otra vez a ${jid} tras resincronizar (nuevo ${info?.key?.id}).`);
            emitir({ evt: 'reenvio', remoteJid: jid, original: key.id, estado: 'enviadoOk' });
            if (alarmasActivas.delete(jid)) {
                emitir({ evt: 'alarmaSesion', accion: 'resuelta', remoteJid: jid });
            }
        } catch (error) {
            logDiagnostico(`Reenvío: no se pudo mandar otra vez ${key.id} a ${jid}:`, error?.message ?? error);
            emitir({ evt: 'reenvio', remoteJid: jid, original: key.id, estado: 'error', detalle: String(error?.message ?? error) });
        }
    }, REENVIO_ESPERA_MS);
}

// Llamar desde `getMessage` en cada reintento ATENDIDO. Al cruzar el umbral
// para el mismo `key.id`, avisa al lado .NET (evento "detectada", pinta la
// alarma en rojo) e intenta el autoarreglo — una sola vez por contacto
// mientras la alarma siga activa, para no borrar la sesión en bucle si
// siguen llegando reintentos del mismo mensaje.
function registrarReintentoYAvisarSiSospechoso(key) {
    const contador = (reintentosPorMensaje.get(key.id) ?? 0) + 1;
    reintentosPorMensaje.set(key.id, contador);

    if (contador >= UMBRAL_REINTENTOS_SOSPECHOSO && !alarmasActivas.has(key.remoteJid)) {
        alarmasActivas.add(key.remoteJid);
        emitir({ evt: 'alarmaSesion', accion: 'detectada', remoteJid: key.remoteJid });
        logDiagnostico(`Sesión sospechosa con ${key.remoteJid}: ${contador} reintentos para el mismo mensaje (${key.id}).`);
        borrarSesionContacto(key.remoteJid).catch((error) => logDiagnostico('Autoarreglo falló:', error));
    } else if (contador === UMBRAL_REINTENTOS_SOSPECHOSO) {
        // Otro mensaje atascado con la alarma del contacto ya activa: la sesión se rehace también, una vez por mensaje (no en bucle), para
        // que el reenvío no salga por la misma sesión rota
        logDiagnostico(`Sesión sospechosa con ${key.remoteJid} otra vez: ${contador} reintentos para ${key.id}.`);
        borrarSesionContacto(key.remoteJid).catch((error) => logDiagnostico('Autoarreglo falló:', error));
    }
    // El mensaje atascado, otra vez como nuevo (ver «Reenviar el mensaje atascado»)
    if (contador === UMBRAL_REINTENTOS_SOSPECHOSO) {
        programarReenvio(key);
    }
}

// Un fallo de la sesión cifrada (Signal) con un contacto: «No open session», «Bad MAC», «SessionError»… (PENDIENTES 186,
// 2026-11-01). En la caja de pruebas, uno de estos sin capturar (en la cola de libsignal, `queue_job.js`) paraba el proceso cada
// minuto y el aviso no salía. No es un fallo del proceso: se apunta y se sigue, y un envío que lo da rehace la sesión de ese contacto.
function esFalloDeSesionCifrada(error) {
    const nombres = ['SignalError', 'SessionError', 'MessageCounterError', 'PreKeyError', 'UntrustedIdentityKeyError'];
    return nombres.includes(error?.name)
        || /Bad MAC|No (open |matching )?sessions?\b|No session record/.test(String(error?.message ?? ''))
        || /[\\/]libsignal[\\/]/.test(String(error?.stack ?? ''));
}

// Un envío que falla al cifrar porque la sesión está rota: «No open session», «No sessions».
function esSesionRotaAlEnviar(error) {
    return /^No (open )?sessions?\b/.test(String(error?.message ?? ''));
}

// Con la sesión rota, borra las de ese contacto y prueba UNA vez más: el fallo es al cifrar, antes de mandar nada, así que no puede
// llegar duplicado. Borra también las de nuestra propia cuenta, porque cada envío se cifra además para nuestros otros dispositivos y el
// error no dice de cuál venía. En un grupo no se reintenta: no se sabe de qué participante es (para eso, «Reparar la conexión»).
async function enviarConUnReintento(jid, contenido) {
    try {
        return await sock.sendMessage(jid, contenido);
    } catch (error) {
        if (!esSesionRotaAlEnviar(error) || jid.endsWith('@g.us')) {
            throw error;
        }
        const borradas = await borrarSesionesDe([jid, sock.user?.id, sock.user?.lid].filter(Boolean));
        logDiagnostico(`Envío a ${jid} con la sesión rota (${error.message}): ${borradas} sesiones borradas, se reintenta una vez.`);
        return await sock.sendMessage(jid, contenido);
    }
}

function emitir(evento) {
    process.stdout.write(JSON.stringify(evento) + '\n');
}

// Deduplicación de mensajes entrantes por `key.id`. Cuando `remoteJid` es un
// `@lid`, Baileys re-dispara `messages.upsert` (`type: 'notify'`) para EL
// MISMO mensaje unos segundos después, ya con `key.senderPn` resuelto — sin
// esto el lado C# ve el mensaje dos veces y dispararía flujos/respuestas por
// duplicado (ver .ApiNotes.md, 2026-09-01). Set acotado por orden de
// inserción; sobrevive a reconexiones (es de módulo) para cubrir también un
// re-envío tras reconectar. Nos quedamos con la PRIMERA copia; el número, si
// faltaba, lo rellena el .NET en el siguiente mensaje.
const idsMensajesVistos = new Set();

function mensajeYaVisto(id) {
    if (!id) {
        return false;
    }

    if (idsMensajesVistos.has(id)) {
        return true;
    }

    idsMensajesVistos.add(id);
    if (idsMensajesVistos.size > 5000) {
        const iterador = idsMensajesVistos.values();
        for (let i = 0; i < 1000; i++) {
            idsMensajesVistos.delete(iterador.next().value);
        }
    }

    return false;
}

function logDiagnostico(...args) {
    console.error('[factorybox-whatsapp]', ...args);
}

// --- Almacén de mensajes enviados (para `getMessage`) ---------------------

// Copia en memoria para el camino rápido; el disco es la fuente de verdad y
// lo que sobrevive a un reinicio. `key.id` -> proto del mensaje.
const mensajesEnviados = new Map();

function rutaMensajeEnviado(id) {
    // `key.id` es alfanumérico (hex en mayúsculas para los nuestros, base64
    // para los de otros clientes). `encodeURIComponent` lo deja como nombre
    // de fichero seguro y reversible.
    return join(CARPETA_MSGSTORE, encodeURIComponent(id) + '.json');
}

function guardarMensajeEnviado(id, message) {
    if (!id || !message) {
        return;
    }

    mensajesEnviados.set(id, message);
    // Tope de memoria entre podas (el disco manda y tiene su propia poda por
    // edad). `Map` conserva orden de inserción → quita los más antiguos.
    if (mensajesEnviados.size > MSGSTORE_MAX_FICHEROS) {
        const it = mensajesEnviados.keys();
        for (let i = 0; i < 500; i++) {
            mensajesEnviados.delete(it.next().value);
        }
    }

    try {
        writeFileSync(rutaMensajeEnviado(id), JSON.stringify({ id, ts: Date.now(), message }));
    } catch (error) {
        logDiagnostico('msgstore: no se pudo persistir el mensaje', id, error);
    }
}

function obtenerMensajeEnviado(id) {
    const enMemoria = mensajesEnviados.get(id);
    if (enMemoria) {
        return enMemoria;
    }

    // Rescate desde disco: el proceso pudo reiniciarse entre el envío y el
    // reintento, o la entrada pudo podarse de memoria pero seguir en disco.
    try {
        const registro = JSON.parse(readFileSync(rutaMensajeEnviado(id), 'utf8'));
        if (registro?.message) {
            mensajesEnviados.set(id, registro.message);
            return registro.message;
        }
    } catch {
        // No está o el fichero está corrupto: se trata como "no encontrado".
    }

    return undefined;
}

// Al arrancar: carga en memoria lo que siga vigente y borra lo caducado o
// ilegible. Se llama también cada pocas horas para que un proceso de vida
// larga no acumule.
function mantenerMsgstore() {
    const ahora = Date.now();
    let cargados = 0;
    let borrados = 0;

    let ficheros;
    try {
        ficheros = readdirSync(CARPETA_MSGSTORE).filter((n) => n.endsWith('.json'));
    } catch (error) {
        logDiagnostico('msgstore: no se pudo listar la carpeta', error);
        return;
    }

    // Si nos hemos pasado del tope, empieza por los más antiguos (por mtime).
    if (ficheros.length > MSGSTORE_MAX_FICHEROS) {
        ficheros = ordenarPorAntiguedad(ficheros);
    }

    for (let i = 0; i < ficheros.length; i++) {
        const ruta = join(CARPETA_MSGSTORE, ficheros[i]);
        const sobraPorTope = ficheros.length - i > MSGSTORE_MAX_FICHEROS;
        try {
            const registro = JSON.parse(readFileSync(ruta, 'utf8'));
            const caducado = typeof registro?.ts !== 'number' || ahora - registro.ts > MSGSTORE_TTL_MS;
            if (sobraPorTope || caducado || !registro?.id || !registro?.message) {
                rmSync(ruta, { force: true });
                mensajesEnviados.delete(registro?.id);
                borrados++;
                continue;
            }
            mensajesEnviados.set(registro.id, registro.message);
            cargados++;
        } catch {
            rmSync(ruta, { force: true });
            borrados++;
        }
    }

    logDiagnostico(`msgstore: ${cargados} mensajes vigentes, ${borrados} caducados/ilegibles borrados.`);
}

function ordenarPorAntiguedad(ficheros) {
    return ficheros
        .map((n) => {
            let mtimeMs = 0;
            try {
                mtimeMs = statSync(join(CARPETA_MSGSTORE, n)).mtimeMs;
            } catch {
                // ignorar
            }
            return { n, mtimeMs };
        })
        .sort((a, b) => a.mtimeMs - b.mtimeMs)
        .map((x) => x.n);
}

function mapMotivoDesconexion(lastDisconnect) {
    const codigo = lastDisconnect?.error?.output?.statusCode;
    // DisconnectReason.loggedOut: la sesión fue cerrada explícitamente
    // (desde el teléfono, o WhatsApp la invalidó) — no hay reconexión
    // posible sin volver a vincular. Cualquier otro motivo (restartRequired,
    // connectionLost, timedOut...) es transitorio y HAY que reconectar: en
    // particular, justo después de escanear el QR, WhatsApp cierra la
    // conexión a propósito (código 515, "reinicio requerido") y espera a
    // que el cliente reconecte solo con las credenciales ya guardadas —
    // esa segunda conexión es la que completa el registro. Sin reconectar
    // aquí, el móvil se queda colgado en "Iniciando sesión..." para
    // siempre (bug real, encontrado en la primera prueba real — ver
    // Iris.Canales.WhatsAppBaileys.ApiNotes.md).
    if (codigo === DisconnectReason.loggedOut) {
        return 'bloqueado';
    }
    return 'desconectado';
}

function tipoAdjuntoBaileys(adjunto) {
    switch (adjunto?.tipo) {
        case 'Imagen':
            return 'image';
        case 'Audio':
            return 'audio';
        // Un GIF se manda como vídeo mudo en bucle (gifPlayback en
        // construirContenido) — así lo espera WhatsApp, no como imagen.
        case 'Gif':
        case 'Video':
            return 'video';
        case 'Archivo':
            return 'document';
        default:
            return null;
    }
}

function extraerTexto(mensaje) {
    // Un chat con "mensajes temporales" (autodestrucción) activados envuelve
    // TODO su contenido en `ephemeralMessage.message` — incluido el texto
    // plano de siempre. Sin desenvolver esto, un mensaje de texto normal en
    // uno de esos chats llega como `null` y el lado C# lo trata como "el
    // contacto respondió con texto vacío" en vez de "no reconocido" (ver
    // WhatsAppCanalAdapter.cs + DespachadorMensajes.cs). 2026-09-17: sospecha
    // fundada de la causa real de un "Esperar respuesta" que guardó vacío en
    // una conversación por `@lid` — sin poder confirmarlo con el log real
    // porque `Diagnostico` no llegaba a producción (arreglado aparte, ver
    // AnfitrionRuntime.cs).
    const contenido = mensaje.message?.ephemeralMessage?.message ?? mensaje.message;
    return (
        contenido?.conversation ??
        contenido?.extendedTextMessage?.text ??
        contenido?.imageMessage?.caption ??
        contenido?.videoMessage?.caption ??
        null
    );
}

function construirContenido(comando) {
    const adjunto = comando.adjuntos?.[0];
    if (!adjunto) {
        return { text: comando.texto ?? '' };
    }

    const campo = tipoAdjuntoBaileys(adjunto);
    if (campo === null) {
        return null;
    }

    return {
        [campo]: { url: adjunto.rutaLocal },
        mimetype: adjunto.mimeType ?? undefined,
        // Un documento se ve con este nombre (el original del archivo subido); sin él, WhatsApp no tiene cómo llamarlo.
        fileName: campo === 'document' ? (adjunto.nombreArchivo ?? undefined) : undefined,
        caption: comando.texto ?? undefined,
        gifPlayback: adjunto.tipo === 'Gif' ? true : undefined,
    };
}

async function manejarComando(comando) {
    if (comando.cmd === 'shutdown') {
        await sock?.end(undefined);
        process.exit(0);
    }

    if (comando.cmd === 'send') {
        if (!sock) {
            emitir({
                evt: 'envio',
                envioId: comando.envioId,
                estado: 'error',
                categoria: 'canalDesconectado',
                detalle: 'El sidecar todavía no tiene una conexión activa.',
            });
            return;
        }

        const jid = comando.destino.idExterno;
        const contenidoBaileys = construirContenido(comando);
        if (contenidoBaileys === null) {
            emitir({
                evt: 'envio',
                envioId: comando.envioId,
                estado: 'error',
                categoria: 'contenidoRechazado',
                detalle: 'Tipo de adjunto no soportado todavía por el sidecar.',
            });
            return;
        }

        emitir({ evt: 'envio', envioId: comando.envioId, estado: 'enColado' });
        try {
            // La sesión cifrada con ese contacto rota (PENDIENTES 186): se rehace y se prueba una vez más
            const info = await enviarConUnReintento(jid, contenidoBaileys);
            // Guardar ANTES de avisar del OK: si el destinatario pide un
            // reintento, `getMessage` tiene que poder encontrarlo.
            guardarMensajeEnviado(info?.key?.id, info?.message);
            emitir({ evt: 'envio', envioId: comando.envioId, estado: 'enviadoOk' });
            // El envío a este contacto salió bien tras el autoarreglo — se
            // considera resuelta la alarma (verde), no solo "parche aplicado".
            if (alarmasActivas.delete(jid)) {
                emitir({ evt: 'alarmaSesion', accion: 'resuelta', remoteJid: jid });
            }
        } catch (error) {
            emitir({
                evt: 'envio',
                envioId: comando.envioId,
                estado: 'error',
                categoria: 'desconocido',
                detalle: String(error?.message ?? error),
            });
        }
    }

    if (comando.cmd === 'desvincular') {
        // Pedido por la app: en la caja, «Desvincular y volver a vincular» de la página de avisos (en IrisFlow, la identidad
        // conectada no está entre las registradas en CuentasDeCanal). sock.logout() avisa a WhatsApp de
        // que este dispositivo deja de estar vinculado (no solo borra
        // ficheros locales, que dejaría el teléfono creyendo que sigue
        // vinculado) y dispara 'close' con loggedOut — el mismo camino que
        // ya limpia auth/ y pide un QR nuevo cuando es WhatsApp quien te
        // desvincula a ti (ver reiniciarSesion()), sin duplicar esa lógica.
        logDiagnostico('Desvinculación pedida por la app.');
        try {
            await sock?.logout();
        } catch (error) {
            logDiagnostico('Fallo al desvincular, se limpia la sesión igualmente:', error);
            await reiniciarSesion();
        }
        return;
    }

    if (comando.cmd === 'listarGrupos') {
        if (!sock) {
            emitir({ evt: 'grupos', grupos: [], error: 'El sidecar todavía no tiene una conexión activa.' });
            return;
        }

        try {
            const grupos = await sock.groupFetchAllParticipating();
            emitir({
                evt: 'grupos',
                grupos: Object.values(grupos).map((g) => ({ jid: g.id, nombre: g.subject })),
            });
        } catch (error) {
            emitir({ evt: 'grupos', grupos: [], error: String(error?.message ?? error) });
        }
    }
}

async function conectar(state, saveCreds) {
    const { version } = await fetchLatestBaileysVersion();

    almacenClaves = makeCacheableSignalKeyStore(state.keys, logger);
    sock = makeWASocket({
        version,
        auth: {
            creds: state.creds,
            // Cache en memoria de las claves de sesión Signal (lo recomienda
            // Baileys): evita ir a disco en cada (des)cifrado. Sin esto, bajo
            // tráfico sostenido la sesión con un dispositivo se puede
            // desincronizar. `state.keys.set` sigue persistiendo en `auth/`.
            keys: almacenClaves,
        },
        logger,
        // Triple [plataforma, navegador, versión] a mano en vez de
        // Browsers.ubuntu('IrisCore') — ese ayudante deja "Ubuntu" como
        // primer elemento (lo que WhatsApp muestra en "Dispositivos
        // vinculados" del teléfono) y mete 'IrisCore' como segundo, que no
        // se ve. El usuario puede renombrarlo luego a mano desde el propio
        // teléfono si quiere.
        browser: ['Factory Box', 'Desktop', '1.0.0'],
        printQRInTerminal: false,
        // Cuando el móvil del destinatario no puede descifrar un mensaje pide
        // un reintento; Baileys llama aquí para recuperar el contenido
        // original y volver a cifrarlo. Sin este callback (el defecto de la
        // librería devuelve `undefined`) el mensaje se queda colgado en
        // "Esperando este mensaje..." y la sesión se desincroniza — ver
        // .ApiNotes.md.
        getMessage: async (key) => {
            const message = obtenerMensajeEnviado(key.id);
            if (message) {
                logDiagnostico(`getMessage: reintento ATENDIDO para ${key.id} (${key.remoteJid}).`);
                registrarReintentoYAvisarSiSospechoso(key);
                return message;
            }
            logDiagnostico(
                `getMessage: reintento NO atendido para ${key.id} (${key.remoteJid}) — el mensaje no está en el almacén.`);
            return undefined;
        },
    });


    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (actualizacion) => {
        const { connection, lastDisconnect, qr } = actualizacion;

        if (qr) {
            emitir({ evt: 'conexion', estado: 'requiereReautenticacion', datosReautenticacion: qr });
            return;
        }

        if (connection === 'open') {
            // `lid` (id oculto de la propia cuenta): útil para la huella de
            // identidad al reconectar (ver .ApiNotes.md) — hoy `IrisCore`
            // solo usa `identidadConectada`.
            emitir({
                evt: 'conexion',
                estado: 'conectado',
                identidadConectada: sock.user?.id ?? null,
                lid: sock.user?.lid ?? null,
            });
            return;
        }

        if (connection === 'close') {
            const codigo = lastDisconnect?.error?.output?.statusCode;
            const estado = mapMotivoDesconexion(lastDisconnect);
            emitir({ evt: 'conexion', estado });

            if (codigo === DisconnectReason.loggedOut) {
                // Las credenciales de esta sesión ya no sirven para nada —
                // sin limpiarlas y volver a empezar, Baileys no genera un QR
                // nuevo y el canal se queda "bloqueado" para siempre, sin
                // ninguna forma de recuperarlo desde la app (bug real,
                // encontrado probando: la ventana mostraba "Bloqueado" pero
                // nunca llegaba el QR — ver Iris.Canales.WhatsAppBaileys.ApiNotes.md).
                reiniciarSesion().catch((error) => logDiagnostico('Fallo al reiniciar sesión:', error));
            } else {
                logDiagnostico(`Conexión cerrada (código ${codigo}), reconectando...`);
                conectar(state, saveCreds).catch((error) => logDiagnostico('Fallo al reconectar:', error));
            }
        }
    });

    // La caja solo avisa: no se escuchan mensajes ni entradas a grupos (en IrisFlow, messages.upsert y
    // group-participants.update).
}

function limpiarCarpetaAuth() {
    for (const nombre of readdirSync(CARPETA_AUTH)) {
        rmSync(join(CARPETA_AUTH, nombre), { recursive: true, force: true });
    }
}

async function reiniciarSesion() {
    logDiagnostico('Sesión cerrada por WhatsApp — limpiando credenciales y generando un QR nuevo.');
    limpiarCarpetaAuth();
    const { state, saveCreds } = await useMultiFileAuthState(CARPETA_AUTH);
    await conectar(state, saveCreds);
}

async function main() {
    // Antes de conectar: recuperar en memoria los mensajes enviados que
    // sigan vigentes (para responder reintentos que lleguen tras un
    // reinicio) y limpiar los caducados. Repetir cada pocas horas para un
    // proceso de vida larga.
    mantenerMsgstore();
    setInterval(mantenerMsgstore, MSGSTORE_PODA_CADA_MS).unref();

    const { state, saveCreds } = await useMultiFileAuthState(CARPETA_AUTH);
    await conectar(state, saveCreds);

    const rl = createInterface({ input: process.stdin });

    // Los comandos se procesan de uno en uno, en orden. `sock.sendMessage` de
    // Baileys no tolera llamadas concurrentes: dos envíos seguidos en la misma
    // ráfaga de un flujo (p. ej. "Enviar mensaje" + "Elegir opción", o un
    // mensaje de rama + el re-menú) se pisaban el estado interno y WhatsApp
    // descartaba el segundo en silencio. Encadenar en una sola promesa
    // serializa sin bloquear el bucle de eventos.
    let colaComandos = Promise.resolve();
    rl.on('line', (linea) => {
        if (!linea.trim()) {
            return;
        }
        let comando;
        try {
            comando = JSON.parse(linea);
        } catch (error) {
            logDiagnostico('Línea de comando no es JSON válido:', linea, error);
            return;
        }
        colaComandos = colaComandos
            .then(() => manejarComando(comando))
            .catch((error) => logDiagnostico('Error manejando comando:', error));
    });
}

// Un fallo de la sesión cifrada con un contacto no para el proceso (PENDIENTES 186): antes, uno sin capturar lo paraba cada minuto en
// bucle. Cualquier otro error sí lo para, y el visor lo vuelve a lanzar.
process.on('uncaughtException', (error) => {
    if (esFalloDeSesionCifrada(error)) {
        logDiagnostico('Fallo de la sesión cifrada (se sigue):', error);
        return;
    }
    logDiagnostico('uncaughtException:', error);
    process.exit(1);
});
process.on('unhandledRejection', (error) => {
    if (esFalloDeSesionCifrada(error)) {
        logDiagnostico('Fallo de la sesión cifrada (se sigue):', error);
        return;
    }
    logDiagnostico('unhandledRejection:', error);
    process.exit(1);
});

main().catch((error) => {
    logDiagnostico('Fallo arrancando el sidecar:', error);
    process.exit(1);
});
