# Formato de los eventos HTTP

Este documento describe el contrato de entrada del motor: la estructura
`Event` en `internal/event`, sus reglas de validación y por qué se
diseñó así. Es la referencia para defender estas decisiones en la
entrevista técnica.

## Qué es un evento y qué no es

Un evento **no es** el request HTTP en vivo. Es la descripción de un
request que **ya ocurrió**, tal como la reportaría el log de un servidor
web, un WAF o un balanceador de carga. El motor de decisión nunca
intercepta tráfico directamente en esta fase del proyecto (esa es la
diferencia entre la "API de decisión basada en metadata" que elegimos y
un "reverse proxy inline", que descartamos en el análisis general).

Como el evento describe algo que ya pasó, puede incluir el
**`status_code`** de la respuesta — y eso es clave, porque las señales
principales del challenge (ratio de 401/403, ratio de 404) están en la
respuesta, no en el pedido.

## Campos del contrato

| Campo | Obligatorio | Tipo | Para qué sirve |
|---|---|---|---|
| `request_id` | Sí | texto | Identifica el evento de forma única. El "árbitro" (`cmd/eval`) lo usa para cruzar la decisión del motor con la etiqueta de verdad |
| `timestamp` | Sí | fecha y hora | Ubica el evento en el tiempo del ataque (no en el reloj de la máquina — ver la sección de tiempo más abajo) |
| `client_ip` | Sí | dirección IP | La entidad "IP" sobre la que se construye el perfil de comportamiento |
| `session_id` | No | texto | La entidad "sesión". Muchos bots y clientes de API no la tienen, y eso es información en sí mismo — no forzamos un valor inventado |
| `method` | Sí | texto | Verbo HTTP tal cual llegó, sin restringir a la lista clásica (ver más abajo) |
| `path` | Sí | texto | La ruta pedida, sin la parte de parámetros |
| `query_params` | No | lista de nombres | Solo los **nombres** de los parámetros, nunca sus valores |
| `status_code` | Sí | número (100–599) | La señal más importante: de acá salen los ratios de error que definen ambos ataques |
| `user_agent` | No | texto | Puede venir vacío |
| `referer` | No | texto | Su ausencia es una señal para el escaneo lento |
| `login_user_hash` | No | texto (huella tipo hash) | Qué cuenta se intentó usar en un login, disfrazada — nunca el email en claro |

Elegimos dejar solo 6 campos obligatorios (`request_id`, `timestamp`,
`client_ip`, `method`, `path`, `status_code`) a propósito: son el mínimo
que cualquier fuente de logs real puede ofrecer, y con esos 6 alcanza
para construir las señales de ambos ataques. Pedir más campos como
obligatorios dejaría afuera a fuentes de datos legítimas que no los
tienen.

## Por qué el método HTTP no está restringido

Al principio pensamos en aceptar solo los verbos clásicos (GET, POST,
PUT...). Decidimos **no hacerlo**: un método raro (`TRACE`, o algo
inventado por una herramienta de fuzzing) puede ser en sí mismo una
señal de escaneo. Si la validación lo rechazara de entrada, el detector
nunca llegaría a verlo.

En cambio, sí validamos que el método sea **sintácticamente válido**
según el estándar HTTP (una palabra sin espacios ni caracteres raros,
de hasta 20 caracteres) y que no venga vacío. Esto separa dos cosas
distintas: "¿es un texto con forma de método HTTP?" (regla de
validación, acá) de "¿es un método sospechoso?" (decisión de un
detector, más adelante, en la Fase 1).

## Por qué el ASN no viaja en el evento

El ASN (el "barrio" de Internet al que pertenece una IP — ver la
sección 6 del análisis general) **no es un dato que el evento traiga**.
Es un dato que se calcula **después**, a partir del `client_ip`, usando
el componente de enriquecimiento (Fase 1). Dos razones:

1. **Separación de responsabilidades.** El evento describe "qué pasó en
   ese request"; el ASN describe "quién es dueño de esa IP", que es un
   dato sobre la IP en general, no sobre ese request en particular. Si
   lo metiéramos en el evento, tendríamos que recalcularlo (o
   confiar ciegamente) en cada uno de los millones de requests de una
   misma IP.
2. **El enriquecimiento puede cambiar o fallar de forma independiente.**
   Si la fuente de ASN está caída, eso no debe impedir que el evento
   sea válido — el motor puede seguir analizando con "ASN desconocido"
   y recalcularlo cuando la fuente vuelva.

El diseño queda preparado para la correlación por ASN porque
`client_ip` es el dato base a partir del cual el enriquecimiento (Fase
1) construye ese contexto adicional, y ese contexto se junta al perfil
de la IP, no al evento individual.

## Cómo se identifican las rutas de autenticación

Para el credential stuffing necesitamos saber cuáles requests son
"intentos de login" (para calcular el ratio de 401/403 y la diversidad
de cuentas). Esto **no es parte de la validación del evento** — es una
pieza aparte, `AuthPathMatcher` (en `internal/event/authpath.go`), por
una razón concreta: qué ruta es "el login" depende de **la aplicación
protegida**, no del formato del evento. Un evento con `path=/login` es
válido tanto si `/login` es el login real como si no lo es; eso lo
decide la configuración, no el contrato de datos.

`AuthPathMatcher` viene con una lista por defecto (`/login`, `/signin`,
`/api/login`, `/oauth/token`, y los prefijos `/auth/`, `/api/auth/`,
`/sso/`) pensada para el generador de tráfico y las aplicaciones que
modela. En un despliegue real, esa lista se leería de configuración,
no del código — el diseño ya está preparado para eso porque
`NewAuthPathMatcher` acepta cualquier lista.

## Reglas de validación

`Validator.Validate` (en `internal/event/validate.go`) aplica estas
reglas y devuelve **todos** los errores encontrados a la vez, no solo
el primero — así, un evento roto en tres lugares distintos se ve
completo en un solo intento, en vez de arreglarse de a un error por
vez.

| Regla | Qué rechaza | Por qué |
|---|---|---|
| `request_id` no vacío | Vacío o solo espacios | Sin esto, el árbitro no puede cruzar la decisión con la etiqueta |
| `timestamp` no vacío y dentro de rango | Fecha vacía, muy vieja o muy futura | Ver la sección de tiempo |
| `client_ip` válida y pública | IP mal formada, o de rangos privados/loopback (`10.x`, `127.x`, etc.) | Una IP privada no se puede enriquecer con ASN real, y en este proyecto señala que el generador de datos está mal armado |
| `method` no vacío, con caracteres válidos, hasta 20 caracteres | Vacío, con espacios, o excesivamente largo | Protege al motor sin prohibir métodos raros (ver arriba) |
| `path` no vacío, empieza con `/`, hasta 2048 caracteres | Vacío, sin `/` inicial, o excesivamente largo | Un path gigante es en sí mismo un intento de agotar la memoria del motor |
| `status_code` entre 100 y 599 | Cualquier otro número | Rango válido del protocolo HTTP |
| `login_user_hash`, si viene, tiene forma de hash (16–128 caracteres hexadecimales) | Un email, un nombre de usuario en texto plano, o un texto demasiado corto | Evita que un dato personal se cuele en este campo por error |

**Caso especial: `session_id` con solo espacios.** No se rechaza. Se
trata como si el campo no hubiera venido. La validación lo ignora, y
`Event.Normalize()` lo convierte en cadena vacía para quien quiera
guardar o reenviar una versión "limpia" del evento.

## Timestamps: validación de rango vs. ventanas del motor

Hay **dos mecanismos distintos** relacionados con el tiempo, y es
importante no confundirlos:

1. **Validación de rango (esta tarea, `Validator`).** Rechaza eventos
   con una fecha claramente rota: demasiado vieja (más de
   `MaxPastAge`, 5 minutos por defecto) o demasiado futura (más de
   `MaxFutureSkew`, 1 minuto por defecto). Es una regla de **higiene de
   datos**: protege contra basura, relojes mal configurados en el
   origen, o un intento de confundir al motor con fechas absurdas.
   Ambos límites son campos del `Validator` y se pueden ajustar.

2. **Manejo de eventos tardíos en las ventanas (Fase 1, todavía no
   implementado).** Cuando el motor arme los perfiles de comportamiento
   por ventanas de tiempo (por ejemplo, "los últimos 5 minutos"), un
   evento válido pero que llega un poco tarde respecto de la ventana
   que ya se cerró necesita una tolerancia propia, que puede ser
   distinta de la tolerancia de validación. Ese evento se cuenta en una
   métrica separada (`late_events_total`), pero **nunca se descarta
   silenciosamente** ni se rechaza como si fuera inválido.

En criollo: la validación de esta tarea es un filtro de "¿esta fecha
tiene sentido?" que corre una sola vez, al entrar el evento. Las
ventanas de la Fase 1 son un mecanismo aparte que decide "¿a qué
bloque de tiempo pertenece este evento, dado que puede llegar
desordenado?" y corre después, dentro del motor.

**Por qué usamos un reloj inyectable (`Clock`).** Si `Validator`
llamara directamente a `time.Now()`, sería imposible escribir un test
que compruebe "un evento de hace 6 minutos se rechaza" sin esperar 6
minutos de verdad. Con `Clock` como interfaz, los tests (y más
adelante el generador de tráfico, que simula 6 horas de ataque en
minutos) usan `ManualClock`, que se mueve con `Set` o `Advance` de
forma instantánea. En producción se usa `SystemClock`, que sí llama al
reloj real.

## Privacidad y seguridad de los datos

El contrato aplica **minimización de datos** desde el diseño:

- **Nunca** transporta contraseñas, tokens ni cookies completas.
- El nombre de usuario o email de un intento de login nunca viaja en
  claro: se reemplaza por `login_user_hash`, una huella (HMAC, no un
  hash reversible) calculada por quien produce el evento. La misma
  cuenta siempre da la misma huella — así se puede contar "cuántas
  cuentas distintas se probaron" — pero la huella no permite recuperar
  el email.
- `query_params` guarda solo **nombres** de parámetros
  (`["id", "page"]`), nunca sus valores. Un valor podría ser un dato
  sensible; el nombre alcanza para medir diversidad de parámetros en
  el escaneo.
- No existe ningún campo para el cuerpo (body) del request.

Estas reglas están verificadas por tests que inspeccionan el JSON
serializado en busca de palabras como `password`, `token` o `cookie`
(`internal/event/json_test.go`).

## Cómo se garantiza que la etiqueta de verdad nunca entra al motor

Esto no depende de que alguien "tenga cuidado" — está garantizado en
tres capas:

1. **El tipo `Event` no tiene ningún campo de etiqueta.** No existe
   `Label`, `AttackType` ni nada parecido.
2. **Un test por reflexión** (`TestEvent_HasNoGroundTruthField`, en
   `internal/event/structural_test.go`) inspecciona los nombres de los
   campos de `Event` y falla si alguno contiene palabras como `label`,
   `truth` o `attack_type` — así, si alguien agrega el campo sin
   querer en el futuro, el test lo frena antes de que llegue a `main`.
3. **Un test sobre el JSON serializado**
   (`TestEventJSON_GroundTruthNeverTravels`) confirma que ni siquiera
   por accidente aparece esa palabra en los datos que viajarían por la
   red hacia el motor.

`internal/groundtruth` (tarea 0.3) va a ser un paquete separado, y el
motor de detección nunca lo va a importar.
