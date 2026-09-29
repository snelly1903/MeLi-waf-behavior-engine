# Decisiones técnicas

Este documento describe las decisiones de arquitectura y diseño del motor de
detección conductual (`waf-behavior-engine`), organizadas por tema: qué
problema resolvía cada decisión, qué se eligió hacer, por qué se eligió esa
opción (incluyendo alternativas descartadas cuando se evaluaron), qué
trade-off se aceptó y qué limitaciones quedan documentadas.

## 1. Arquitectura general

**Nombre y ubicación del repositorio.** `waf-behavior-engine`, dentro de
`~/Desktop/M/`, clonado desde el repositorio remoto ya creado en GitHub
(`snelly1903/MeLi-waf-behavior-engine`). El repo llegó vacío salvo el
`README.md` por defecto, que se reemplazó por el esqueleto del proyecto.

**Idioma.** Código, nombres de paquetes, funciones y comentarios en inglés
(convención estándar del ecosistema Go). Documentación (`README.md`,
`docs/`) en español, porque el objetivo del challenge es entender y poder
defender cada decisión, no solo tener el código funcionando.

**Estructura de carpetas.** `cmd/` para los programas ejecutables
(`datagen`, `eval`, `engine`, y más adelante herramientas de tuning/carga)
e `internal/` para el código reutilizable, siguiendo la convención estándar
de Go: todo lo que vive bajo `internal/` no puede ser importado por otro
módulo fuera de este repositorio.

**Versión de Go.** `go.mod` fijó inicialmente `go 1.23.1`, la versión
instalada en la máquina de desarrollo (Apple M3, 16 GB RAM), que cumplía de
sobra el mínimo exigido por el challenge (Go 1.22+). Más adelante, al fijar
las versiones del SDK de OpenTelemetry, el `go` directive subió
automáticamente a `1.25.0` (las versiones actuales del SDK ya piden un Go
más nuevo; Go descargó su propio toolchain sin intervención manual y el
proyecto siguió compilando y pasando todos los tests) y después,
específicamente para resolver una vulnerabilidad de la librería estándar
(ver sección 9), a `1.25.14`.

**Qué se creó en el arranque.** `go.mod`, `Makefile` (objetivos `test`,
`fmt`, `vet`), `.gitignore` (excluye `/data/`, binarios y archivos de
macOS/editores) y el esqueleto de `README.md` con el entorno de pruebas
documentado, según lo exige el challenge.

### Separación estructural del ground truth: principio que atraviesa todo el proyecto

**Problema.** El motor de detección nunca debe poder "ver" la etiqueta real
(`legit` / `credential_stuffing` / `slow_scan`) de un evento: si pudiera,
cualquier medición de su desempeño quedaría contaminada.

**Decisión.** El paquete `internal/groundtruth` contiene las etiquetas.
Ninguna parte del motor de detección (`cmd/engine`, `internal/engine`,
`internal/httpapi`, ni ningún detector) importa ese paquete. La dependencia
va en un solo sentido: `groundtruth` importa `event`, `event` nunca importa
`groundtruth`. `internal/eval` e `internal/datagen` son, deliberadamente,
los únicos paquetes del proyecto que sí importan `internal/groundtruth` —
la regla de aislamiento nunca fue "nadie puede ver el ground truth", fue
"el motor nunca lo ve"; el evaluador existe precisamente para comparar el
ground truth con las decisiones, así que verlo es su trabajo, no una
excepción a la regla.

**Motivo.** Esto se verifica con tests dedicados, para que la garantía no
dependa solo de disciplina al escribir código sino de que el propio código
la haga cumplir: un test por reflexión sobre `Event` falla si alguna vez se
agrega un campo con nombre parecido a `label`/`truth`/`attack_type`, y un
test sobre el JSON serializado confirma que esas palabras tampoco aparecen
en los datos que viajarían por la red (detalle de estos tests en la sección
2).

**Limitación conocida.** Es una garantía estructural sobre el *contrato*
del evento, no una prueba formal de que ninguna futura línea de código
pueda filtrar la etiqueta por otro camino (por ejemplo, un campo de texto
libre mal usado) — las pruebas de aislamiento son una red de seguridad
concreta, no una demostración matemática.

### Servicio HTTP mínimo de ingestión y decisión: `cmd/engine`

**Problema.** Hacía falta una primera tubería completa (HTTP → validación →
decisión) antes de construir ningún detector real, para no acoplar el
diseño de la API a un modelo de detección todavía inexistente.

**Decisión.** Un servicio HTTP que recibe un evento por `POST /v1/events`,
lo valida y devuelve una decisión. En su primera versión, la decisión
siempre era `ALLOW`, con `AttackVector=unknown` (`engine.AllowAllDecider`).
Tres paquetes nuevos, cada uno con una sola responsabilidad:

- `internal/engine`: la abstracción `Decider` —
  `Decide(ctx, event.Event) decision.Decision` — y su implementación
  inicial `AllowAllDecider`. Cuando existiera un detector real, iba a
  implementar esta misma interfaz (lo que efectivamente ocurrió con
  `BehavioralDecider`, ver sección 8).
- `internal/httpapi`: la capa HTTP — decodifica JSON, normaliza y valida
  con `event.Validator` (reutilizado tal cual del contrato de eventos, sin
  duplicar ninguna regla), y le pasa el evento ya validado al `Decider`. No
  sabe nada de cómo se toma una decisión.
- `cmd/engine`: arma las piezas
  (`event.NewValidator(event.SystemClock{})` + el `Decider` vigente +
  `httpapi.NewServer(...)`) y levanta `http.ListenAndServe`.

**Motivo — `Decider` recibe `context.Context` desde el día uno.** Aunque
`AllowAllDecider` no lo usaba todavía, la interfaz ya lo pedía, para poder
propagar después cancelación del cliente HTTP, tracing de OpenTelemetry, o
timeouts de dependencias reales (un store, una llamada al LLM), sin tener
que rediseñar la interfaz ni tocar a cada implementación existente cuando
eso llegara. La capa HTTP pasa `r.Context()` tal cual. `Decide`
deliberadamente no devolvía `error` en esa primera versión: en esa etapa no
existía ningún modo de falla real (ninguna dependencia externa que pudiera
fallar), así que agregarlo habría sido anticipar una necesidad que todavía
no existía.

**Trade-off — `Explanation` fijo también en `ALLOW`.** El contrato de
`decision.Decision` solo exige `Explanation` para `CHALLENGE`/`BLOCK`, pero
se decidió incluirlo siempre, con un texto fijo y determinista (en la
primera versión, `"no behavioral detector is implemented yet; default
policy is ALLOW"`), para que incluso una decisión de `ALLOW` quedara
auditable desde el primer día, sin esperar a que existiera un motor real.

### `BehavioralDecider`: combinar la evidencia de varios detectores

**Problema.** Una vez que existieron tres detectores reales (credential
stuffing, slow scan, anomalía estadística — secciones 4, 5 y 6), hacía
falta un punto único que los alimentara con cada evento, combinara su
evidencia y aplicara una política de decisión configurable.

**Decisión.** `cmd/engine` arma un `engine.BehavioralDecider`, que
alimenta a los tres detectores con cada evento
(`Observe` en cada uno, después `Evaluate` en cada uno — el orden entre
detectores entre sí no importa porque no comparten estado, pero el de
`Observe` antes que `Evaluate`, para el mismo evento, sí es parte del
contrato de cada detector), selecciona el hallazgo (`Finding`) principal, y
aplica la `Policy` (umbrales, ver sección 8) para decidir
`ALLOW`/`CHALLENGE`/`BLOCK`.

**`FinalRiskScore` = el máximo entre los `Finding` disparados, nunca la
suma ni el promedio.** Cada detector mide algo distinto con su propia
escala heurística; sumarlos habría inventado un número sin significado.

**Generalización a N detectores.** Con dos detectores, comparar a mano
alcanzaba. Al agregar el tercero, la función de selección del principal ya
no podía extenderse sin reescribirse — la misma "regla de tres" que ya
había decidido, en otro contexto (sección 3), cuándo extraer un patrón
repetido. `internal/engine` agregó una interfaz privada `detector`
(`Observe`/`Evaluate`/`Sweep`), definida donde se consume — los tres
detectores ya la cumplían tal cual, sin tocarles ninguna firma. El
constructor `NewBehavioralDecider` sigue recibiendo los tres detectores
como parámetros explícitos y tipados (no una lista genérica), para que el
sitio de construcción en `cmd/engine` quede legible. Prioridad de
desempate fija entre detectores: `credential_stuffing(0) > slow_scan(1) >
statistical_anomaly(2)` — el más específico gana un empate exacto; el
genérico es el último recurso.

**Deuda resuelta: `finding.Finding` con `EntityID` estructurado.** En un
primer momento, `finding.Finding` no tenía ningún campo estructurado para
indicar qué entidad (IP o sesión, y cuál) había originado un hallazgo —
esa información solo vivía, en texto libre, dentro de `Explanation`. Se
agregó `EntityID string`, con el mismo formato de prefijo que
`decision.Decision.EntityID` (`"ip:..."`, `"session:..."`, y
`"network:..."` para credential stuffing). Se evaluó explícitamente agregar
también un `EntityType` separado y se descartó: `decision.Decision` nunca
tuvo uno, usa el mismo prefijo desde el día uno, y `BehavioralDecider`
nunca necesita ramificar sobre el tipo de entidad, solo copiar el
`EntityID` de la evidencia principal.

**`cmd/engine`, credential stuffing sin ASN real por defecto:
`credstuffing.UnavailableNetworkResolver`.** Tipo de producción (no un
fake de test) cuyo `Resolve` siempre devuelve `ok=false`, así que ninguna
IP entra jamás a ninguna correlación — el detector queda estructuralmente
inerte pero corriendo de verdad. Se evaluaron tres alternativas: (1) este
resolver placeholder — la elegida; (2) un `*credstuffing.Detector` nulable
en `BehavioralDecider`, tratado como "desactivado" — descartada, obliga a
chequeos de `nil` en cada punto de uso, con riesgo de panic si alguno se
olvida; (3) reutilizar el `fakeResolver` de los tests — descartada
explícitamente, sería un fake de test terminando en producción. Reemplazar
por un resolver real (sección 7), cuando existe un proveedor, es cambiar
una sola línea en `cmd/engine/main.go`, sin tocar `BehavioralDecider`.

**Concurrencia.** `BehavioralDecider` no agrega ningún estado mutable
propio — solo punteros a detectores (ya seguros para concurrencia por
diseño propio) y un `Policy` (value type inmutable). `Decide` es seguro
para llamadas concurrentes porque sus dependencias ya lo son. Confirmado
con `go test -race`.

**Sin interfaces nuevas para inyectar dobles de test en los detectores.**
Se evaluó una interfaz angosta (`Observe`/`Evaluate`) para poder inyectar
dobles de test en `BehavioralDecider` y se descartó: había una sola
implementación de cada ataque, y los tests podían armar escenarios reales
con umbrales pequeños — habría sido sobrearquitectura para un solo
consumidor real en ese momento (la interfaz `detector` privada, descrita
arriba, llegó recién cuando hizo falta un tercer consumidor).

### `internal/wiring`: la construcción del motor, reutilizable

**Problema.** `buildServer`/`buildCredentialStuffingResolver` vivían
inline en `cmd/engine/main.go` (`package main`, no importable), pero hacía
falta poder construir el mismo motor desde otros programas (microbenchmark
y load test, ver sección 11) sin duplicar la lógica de ensamblado.

**Decisión.** Se extrajo `internal/wiring`, refactor puro y verificado sin
cambio de comportamiento. Se agregaron además `BuildDecider`/
`BuildDeciderWithResolver` (decider sin la capa HTTP, para los
microbenchmarks) y `BuildDeciderWithConfigs`/`BuildServerWithConfigs` — los
tres `Config` de detector como parámetro explícito, nunca desde variables
de paquete.

**Motivo.** El load test necesitaba medir la configuración final
congelada tras la calibración (sección 10), mientras `cmd/engine` seguía
sirviendo su configuración por defecto — sin este parámetro explícito no
había forma de pedirle a `internal/wiring` esa configuración sin duplicar
toda la lógica de construcción de detectores en `cmd/loadtest`.
`internal/wiring` sigue sin importar `internal/datagen` (producción nunca
debe depender de un generador de datos de prueba): el resolver ya
construido se pasa como parámetro, quien llama decide de dónde sale.

**Corrección posterior — `wiring.FinalConfigs()`/`FinalPolicy()` como
única fuente de verdad.** Se detectó que `cmd/engine` seguía sirviendo la
configuración por defecto sin calibrar, mientras la infraestructura de
tuning ya evaluaba con la configuración final calibrada — una brecha real
entre lo que el motor decía servir y lo que se había validado.
`internal/wiring.FinalConfigs()`/`FinalPolicy()` pasaron a ser la única
fuente de verdad de la configuración runtime final; las variables de
paquete que usan `BuildDecider`/`BuildServer` se inicializan desde ahí,
nunca desde la configuración por defecto directamente. `cmd/engine` usa
`wiring.FinalPolicy()` como default de sus flags
`--challenge-threshold`/`--block-threshold` (overrideables). La
configuración baseline original (sin calibrar) sigue viviendo
exclusivamente en sus funciones de default, consumida solo por la
infraestructura de comparación baseline-vs-final del tuning — nunca
expuesta como default de `internal/wiring`. No fue un re-tuning: ningún
valor cambió, solo se cerró la brecha de wiring.

## 2. Validación de eventos

### Contrato del evento HTTP

**Campos obligatorios.** Solo 6: `request_id`, `timestamp`, `client_ip`,
`method`, `path`, `status_code`. Es el mínimo que cualquier fuente de logs
real puede ofrecer y alcanza para construir las señales de ambos ataques.
El detalle completo está en `docs/formato-eventos.md`.

**Método HTTP sin restringir a la lista clásica.** Se valida que sea
sintácticamente correcto (sin espacios, hasta 20 caracteres) pero no se
limita a GET/POST/etc. Un método inusual (`TRACE`, uno inventado) puede ser
una señal de escaneo — decidir eso es trabajo del detector, no de la
validación del contrato.

**`client_ip` como `net/netip.Addr`, no como `string`.** Se eligió el tipo
de la librería estándar `net/netip` en lugar de guardar la IP como texto.
Ventajas: una IP mal formada falla al deserializar el JSON antes de llegar
a la validación explícita, las comparaciones y los usos como clave de mapa
(perfiles por IP, sección 3) no generan asignaciones de memoria extra, y el
tipo expone directamente `IsPrivate()`, `IsLoopback()` y similares para la
regla de "solo IPs públicas".

**ASN fuera del evento.** El ASN no viaja en el contrato: se calcula
después, a partir de `client_ip`, en el componente de enriquecimiento
(sección 7). Razón: el ASN es un dato sobre la IP en general, no sobre un
request puntual, y su disponibilidad no debe condicionar si un evento es
válido.

**Rutas de autenticación como componente separado (`AuthPathMatcher`).**
Qué ruta es "el login" depende de la aplicación protegida, no del formato
del evento — por eso no es una regla de validación, sino un matcher
configurable aparte (`internal/event/authpath.go`), con una lista por
defecto pensada para el generador de tráfico. Se reutiliza tal cual en el
baseline de rate limiting (sección 10) y en el detector de credential
stuffing (sección 4).

**Dos tolerancias de tiempo distintas, y por qué no son lo mismo.** La
validación del evento (`Validator`, con `MaxPastAge` = 5 min y
`MaxFutureSkew` = 1 min, ambos configurables) rechaza fechas claramente
rotas — es higiene de datos, corre una sola vez al entrar el evento. El
manejo de eventos tardíos dentro de las ventanas de tiempo del motor es un
mecanismo aparte (el watermark de la sección 3), con su propia tolerancia,
que nunca descarta un evento en silencio sino que lo cuenta en una métrica.
Confundir estos dos mecanismos fue un riesgo identificado y evitado a
propósito.

**Reloj inyectable (`Clock`, con `SystemClock` y `ManualClock`).** Permite
testear reglas de tiempo ("un evento de hace 6 minutos se rechaza") sin
esperar minutos reales, y es el mismo mecanismo que usa el generador de
tráfico para simular horas de ataque en segundos de ejecución, y que
reutiliza después el caché de ASN (sección 7) para su TTL.

**`session_id` con solo espacios no es un error.** Se normaliza a cadena
vacía (`Event.Normalize()`) en lugar de rechazarse — se trata como si el
campo no hubiera venido, ya que muchos clientes legítimos (apps móviles,
API) no tienen sesión.

**`login_user_hash` con forma de hash, nunca el email.** Se valida que sea
una cadena hexadecimal de 32 a 128 caracteres. El nombre de usuario real
nunca se guarda ni se transmite en este contrato — decisión de
minimización de datos, verificada con tests sobre el JSON serializado.

**Errores de validación como valores centinela unidos con
`errors.Join`.** `Validate` devuelve todos los problemas encontrados a la
vez (no solo el primero), y cada regla tiene su propio error exportado
(`ErrEmptyRequestID`, `ErrInvalidStatusCode`, etc.) comprobable con
`errors.Is`. Esto hace que los tests sean específicos por regla y que un
evento roto en varios campos se diagnostique completo en un solo intento.

### Garantías estructurales de aislamiento del ground truth y de datos sensibles

**Garantía de que el ground truth no entra al motor, en tres capas:** (1)
el tipo `Event` no tiene ningún campo de etiqueta, (2) un test por
reflexión falla si alguna vez se agrega un campo con nombre parecido a
`label`/`truth`/`attack_type`, (3) un test sobre el JSON serializado
confirma que esas palabras tampoco aparecen en los datos que viajarían por
la red.

**Ajuste posterior — los tests de aislamiento comprueban la ausencia de
claves JSON exactas, no la ausencia de palabras sueltas en todo el
documento serializado.** Se corrigieron
`TestLabeledEvent_Payload_NeverCarriesLabel` (en
`internal/groundtruth/label_test.go`) y
`TestEventJSON_GroundTruthNeverTravels` (en
`internal/event/json_test.go`). Motivo: una fuga del ground truth solo
puede entrar como un campo nuevo, así que comprobar la clave exacta es una
verificación precisa; buscar substrings en todo el JSON es una
aproximación que puede dar falsos positivos (un campo legítimo que por
casualidad contenga la palabra) o pasar por alto una fuga con otra forma.

**El test de privacidad de credenciales
(`TestEventJSON_NeverCarriesCredentialLikeKeys`) se dejó deliberadamente
distinto, con la razón documentada en el propio archivo.** Una credencial
filtrada no necesariamente entra como una clave nueva: puede colarse como
el *valor* de un campo que ya existe (por ejemplo, alguien pega una
contraseña dentro de `UserAgent` por error) — ahí sí corresponde buscar por
substring. Queda anotado, además, que esta prueba es una red de seguridad
con una lista fija de palabras, no una garantía: la validación,
minimización y sanitización real de datos sensibles en la ingesta y en los
logs del motor sigue siendo trabajo pendiente, no implementado.

**`LabeledEvent.Payload()`, no `ToEvent()` (nombre elegido por decisión
explícita).** Vive en `internal/groundtruth`, no en `internal/event` — es
la única estructura del proyecto que junta un `event.Event` con su
`Label`. `Payload()` devuelve únicamente la parte `Event` de un
`LabeledEvent` — es lo único que el generador de tráfico debe enviarle al
motor. Un test (`TestLabeledEvent_Payload_NeverCarriesLabel`) serializa el
resultado de `Payload()` y confirma que ninguna palabra del vocabulario de
etiquetas (`label`, `credential_stuffing`, `slow_scan`, `legit`) aparece en
esos bytes. `LabeledEvent.Validate` reutiliza `event.Validator` en lugar de
duplicar sus reglas: si una regla de validación de evento cambia,
`groundtruth` la hereda automáticamente.

### Capa HTTP: `internal/httpapi`

**Decodificación, normalización y validación.** `internal/httpapi`
decodifica el JSON, normaliza y valida con `event.Validator` (reutilizado
tal cual, sin duplicar ninguna regla) antes de pasarle el evento al
`Decider`.

**Dos códigos de error, según qué falló.** `400 Bad Request` cuando el
body no es JSON válido (`error: "invalid_json"`); `422 Unprocessable
Entity` cuando el JSON es válido pero el evento no pasa
`event.Validator.Validate()` (`error: "validation_failed"`, con el texto ya
combinado por `errors.Join` como `message`, sin desglosar campo por campo —
mantenerlo simple). `405 Method Not Allowed` con header `Allow` para el
método incorrecto. Los tres casos comparten el mismo formato de cuerpo
(`errorResponse{Error, Message}`), para que quien integre contra esta API
tenga un único formato de error que parsear.

**Límite de tamaño del body.** `http.MaxBytesReader` a 64 KiB en
`POST /v1/events` — un evento es un objeto JSON chico; esto evita que un
body arbitrariamente grande consuma memoria antes de llegar siquiera a la
validación.

**Verificación manual con `curl` contra el servicio real.** Confirmó el
mismo comportamiento que los tests, incluyendo un detalle real: un evento
con timestamp fijo del pasado (por ejemplo, de una prueba escrita minutos
antes) es rechazado por `ErrTimestampTooOld` al usar `event.SystemClock{}`
— el mismo comportamiento correcto que ya garantizaba el `Validator`, ahora
visible en vivo contra un reloj real en vez de uno simulado.

## 3. Perfiles temporales y ventanas

### `internal/profile`: qué es y qué no es

**Problema.** El futuro motor necesitaba "recordar" comportamiento
reciente de una IP y, si existe, de una sesión, dentro de una ventana
temporal, para que los detectores pudieran razonar sobre patrones
agregados en vez de eventos aislados.

**Decisión.** `internal/profile.Store` acumula observaciones y expone
métricas agregadas (`Metrics`) para que un detector las consuma. No decide
ninguna acción por sí mismo.

### Eventos fuera de orden: el mecanismo de watermark

**Problema identificado antes de implementar.** El diseño original
(calcado del recorte por adelante que ya usaba el baseline de rate
limiting, sección 10) asumía orden cronológico, válido ahí porque el
generador de datos escribe `events.jsonl` ya ordenado. Pero
`internal/profile` recibe eventos desde `net/http`, donde dos requests
concurrentes pueden procesarse en cualquier orden respecto a sus propios
`Event.Timestamp`.

**Decisión.** Cada clave (IP o sesión) mantiene un **watermark** — el
máximo `Timestamp` visto hasta ahora para esa clave —, que nunca retrocede
(`if obs.timestamp.After(state.watermark) { state.watermark =
obs.timestamp }`). La ventana se interpreta siempre respecto al watermark,
nunca respecto al evento que acaba de llegar: un evento atrasado pero
todavía dentro de `[watermark-Window, watermark]` cuenta; uno anterior a
ese corte nunca se agrega, y tampoco puede "revivir" observaciones que ya
habían expirado, porque el watermark con el que se calcula el corte
tampoco retrocede para él.

**Trade-off — `Observe` pasó de O(1) amortizado a O(k).** El truco del
baseline de rate limiting (recortar solo por adelante de una cola
ordenada) deja de ser válido si el orden de llegada no está garantizado —
insertar un evento fuera de orden puede dejar la cola sin ordenar, así que
ya no alcanza con mirar el frente. La solución elegida fue la más simple
posible: en cada `Observe`, filtrar toda la cola de esa clave contra el
corte actual (recalculado con el watermark ya actualizado) y agregar la
observación nueva si corresponde — O(k), con k = observaciones retenidas
para esa clave dentro de la ventana. Se decidió explícitamente priorizar
corrección y simplicidad por sobre preservar la complejidad O(1): para el
volumen de este challenge, k está acotado por cuánto tráfico generó una
sola entidad dentro de una sola ventana (chico incluso en escenarios de
ataque), y una estructura de datos más compleja (por ejemplo, un árbol
balanceado por timestamp para mantener el orden con inserciones
arbitrarias) sería optimizar algo que todavía no es un problema medido.

**El mismo patrón, reimplementado de forma autocontenida tres veces más.**
`internal/credstuffing` (sección 4) e `internal/slowscan` (sección 5)
necesitaron el mismo mecanismo de watermark para sus propias ventanas, y en
ambos casos se evaluó explícitamente extraer un `internal/window` genérico
del que dependieran todos los consumidores — y se descartó cada vez:
mantener cada componente autocontenido evita modificar un componente ya
probado sin necesidad, dado el cronograma corto del challenge. Con tres
implementaciones independientes del mismo patrón, la extracción queda como
una limpieza cada vez más razonable para un trabajo futuro, pero nunca
llegó a ser necesaria dentro del alcance del challenge. El detector de
anomalías estadísticas (sección 6), en cambio, no reimplementa el patrón:
construye su propio `*profile.Store` privado y lo consulta directamente.

**Un solo `Window` por `Store`, confirmado.** Si en el futuro hicieran
falta varios tamaños de ventana (por ejemplo, un detector que mira 5
minutos y otro que mira 24 horas), la solución es construir `Store`
independientes, cada uno observando los mismos eventos. Se descartó pasar
un `window` explícito por cada llamada a `Snapshot` (más flexible) porque
abría un error silencioso: pedir una ventana de consulta más ancha que la
ventana de retención del `Store` daría un resultado truncado sin ningún
aviso.

**`NewStore(window) (*Store, error)`, sin panic.** `window <= 0` devuelve
`ErrInvalidWindow` — mismo patrón de validación explícita usado en el
resto del proyecto (baseline de rate limiting, `credstuffing`, etc.),
nunca un reloj real invocado internamente.

### Qué se retiene por observación, y qué nunca se retiene

Se retiene únicamente: `timestamp`, `path`, `status_code`, "tiene o no
tiene referer" (nunca su contenido), `login_user_hash` (ya hasheado desde
el contrato de eventos — nunca un username ni un email en claro, así que
reusarlo acá no agrega riesgo de privacidad nuevo), y `session_id`. Nunca
se retienen: el body del request (nunca existió en `Event`), `UserAgent`,
los valores de `QueryParams` (ni falta hacían para las métricas pedidas),
ni el contenido de `Referer`.

### Limpieza de memoria: dos mecanismos con propósitos distintos

1. El recorte automático en cada `Observe`, determinista y basado
   exclusivamente en `Event.Timestamp` — acota el tamaño de la cola de
   cada clave individual.
2. `Sweep(now, idleTTL)`, manual y opcional — resuelve lo que el recorte
   automático no puede: una IP que mandó un solo request y nunca volvió
   queda con una entrada residual en el mapa para siempre, porque nada
   dispara su limpieza si no llegan más eventos suyos.

**Motivo.** "¿Ya pasó suficiente tiempo real sin noticias de esta
entidad?" es deliberadamente la única pregunta de todo este componente que
toca un reloj real — porque es una pregunta operativa (cuánta memoria se
usa), no una pregunta de detección (que siempre usa tiempo de evento).
`Sweep` recibe `now` como parámetro (nunca `time.Now()` internamente), así
que sigue siendo determinista y testeable; conectarlo a un scheduler real
(un ticker en `cmd/engine`) quedó fuera de alcance y no se implementó.

### Concurrencia y copias defensivas

**Un `sync.Mutex` por índice (IP y sesión), no uno global.** Así una
escritura sobre perfiles de IP no bloquea una lectura de perfiles de
sesión. `Snapshot` nunca modifica el mapa — copia el slice retenido antes
de soltar el lock. Confirmado sin condiciones de carrera con
`go test -race` sobre escenarios de escritura concurrente (misma IP desde
200 goroutines; y 10 IPs × 50 goroutines cada una, más una sesión
compartida entre todas, para ejercitar también el mutex del índice de
sesiones).

**`Metrics` es siempre una copia propia del snapshot.** El slice de
observaciones se copia antes de agregar, y el cálculo de métricas arma un
`PathCounts` nuevo en cada llamada — modificar el `Metrics` devuelto
(incluido su mapa) nunca afecta al estado interno del `Store` ni a un
snapshot posterior.

**Sin interfaz `Profiler` separada de entrada.** Mismo criterio aplicado
más tarde a `engine.Decider`: cuando existiera el primer detector real que
consumiera este `Store`, ese paquete definiría su propia interfaz angosta
con lo que necesitara, en su propio código — no antes, con un solo
consumidor hipotético.

**Limitación conocida.** El caso NAT (una IP con varias sesiones legítimas
detrás) reporta `DistinctSessions` correctamente, pero cualquier señal a
nivel IP sigue "viendo" el agregado de todas esas sesiones juntas — la
misma limitación estructural de cualquier señal por IP que se documenta,
con más detalle, en las secciones 4, 5 y 10 (baseline de rate limiting).

## 4. Credential Stuffing

### `internal/credstuffing`: qué es y qué no es

**Problema.** Detectar credential stuffing distribuido de bajo volumen por
IP — un patrón que un rate limiter tradicional por IP estructuralmente no
puede ver. El baseline de rate limiting (sección 10) ya había demostrado
con datos reales que esa técnica falla contra este patrón (recall 0% en
los tres escenarios de reporte).

**Decisión.** El detector correlaciona actividad entre múltiples IPs de un
mismo grupo de red dentro de una ventana, sin depender de que ninguna IP
individual supere ningún umbral. Dos paquetes nuevos: `internal/finding`
(el tipo `Finding`, compartido por todos los detectores del proyecto) e
`internal/credstuffing` (el detector en sí). `Finding` reutiliza
`decision.AttackVector` y `decision.ContributingSignal` tal cual, sin
duplicar esos tipos.

### Correlación por grupo de red, no por IP individual

**Decisión.** El estado no está indexado por IP ni por sesión (eso ya lo
cubre `internal/profile`, sección 3) — está indexado por grupo de red.
Cada observación agrega su IP a un *conjunto*, no a un contador: una sola
IP mandando mil requests solo aporta 1 al conteo de IPs distintas, así que
un flood de una sola IP estructuralmente nunca puede cruzar
`MinDistinctIPs` por sí solo — sale gratis de usar un conjunto, no de un
caso especial en el código.

**`NetworkResolver`: interfaz mínima, definida donde se consume.** Mismo
criterio que `engine.Decider`: la interfaz vive en `internal/credstuffing`,
no en quien la vaya a implementar. Los tests usan un `fakeResolver`
exclusivamente en `_test.go`; el enriquecimiento real de ASN vive aparte
(sección 7) y lo satisface por tipado estructural, sin que
`internal/credstuffing` lo importe nunca.

**IP no resoluble: excluida de toda correlación, deliberadamente
conservador.** Si `Resolve` devuelve `ok=false`, el evento no crea ni
contamina ningún grupo. Se descartó agrupar todo lo "desconocido" en un
único balde global porque mezclaría tráfico legítimo no relacionado de
todo el mundo en una falsa campaña. **Limitación conocida, documentada
como tal, no como bug:** un atacante detrás de una IP no resoluble es
invisible para este detector.

### El gate conjuntivo y el piso del `RiskScore`

**Señales, por grupo de red, dentro de la ventana:** IPs distintas,
cuentas distintas (`login_user_hash`, excluyendo vacío — misma convención
que `internal/profile.Metrics.DistinctAccounts`), intentos totales, y
ratio de 401/403. Solo se observan eventos de rutas de autenticación
(`event.AuthPathMatcher`, reutilizado tal cual del contrato de eventos).

**Decisión — gate conjuntivo (AND, no un promedio que compensa señales
débiles con fuertes).** `Triggered` exige las cuatro condiciones a la vez:
`DistinctIPs≥MinDistinctIPs`, `DistinctAccounts≥MinDistinctAccounts`,
`TotalAttempts≥MinAttempts`, `FailedRatio≥MinFailedRatio`. Es la defensa
principal contra falsos positivos: un tenant legítimo alojado sobre el
mismo ASN simulado que el pool atacante puede tener muchas IPs y muchas
cuentas, pero sus logins mayormente tienen éxito — nunca cruza el umbral de
ratio, así que nunca dispara, sin importar diversidad. Se verificó también
contra dos casos "parciales": muchos fallos con pocas cuentas (posible
brute-force de una sola cuenta desde muchas IPs — no es el patrón que
busca este gate) y muchas cuentas con pocos fallos (login masivo
legítimo).

**Corrección aplicada: `RiskScore` nunca puede dar 0 cuando `Triggered` es
`true`.** La fórmula original (`1 - umbral/valor` por señal, promediado)
daba exactamente 0 en las cuatro componentes cuando las señales estaban
justo en su umbral — y sin embargo `Triggered` ya era `true` ahí, porque
el gate usa `≥`. Un detector que disparó no puede reportar riesgo cero:
sería contradictorio para quien lea la decisión. **Solución aplicada:** un
piso configurable, `ScoreFloor ∈ (0,1)`, estrictamente entre 0 y 1, con
`RiskScore = ScoreFloor + (1-ScoreFloor)·promedio_ponderado`. Sigue siendo
puramente heurístico — arranca en `ScoreFloor` apenas se cruzan los cuatro
umbrales, y crece hacia 1 (sin tocarlo nunca) cuanto más se los supera —
nunca se presenta como una probabilidad calibrada, misma advertencia que
`decision.Decision.ConfidenceScore` desde su contrato original (sección 1).

**`login_user_hash` vacío.** Cuenta en `TotalAttempts` y en el ratio
401/403, pero nunca se agrega al conjunto de cuentas distintas — mismo
criterio que `internal/profile`.

**Sin umbrales de `CHALLENGE`/`BLOCK` en este detector.** Esos umbrales
son configuración de la `Policy` del motor (sección 8), no de cada
detector — este entrega solo `Triggered` + `RiskScore`.

**Concurrencia y limpieza.** Un único `sync.Mutex` (acá alcanza con uno
solo: a diferencia de `internal/profile`, hay un solo índice — por grupo
de red —, no dos). `Evaluate` copia el estado antes de soltar el lock.
`Sweep(now, idleTTL)` por simetría con `internal/profile`, aunque la
cardinalidad de grupos de red es naturalmente chica (a lo sumo unos pocos
miles de ASN reales), así que el riesgo de crecimiento sin límite es menor
acá. Confirmado sin condiciones de carrera con `go test -race`.

### Generación de tráfico de ataque para probar este detector

**Refactor previo: `DefaultLoginPath` compartido.** Se movió a una
constante reutilizada también por el generador de campañas de credential
stuffing, así el ataque apunta al mismo endpoint que navegan los usuarios
legítimos, no a una aplicación simulada distinta.

**`IPPool.DistinctAddrs`.** El credential stuffing necesita `IPCount`
direcciones distintas (sin reemplazo), a diferencia del sorteo con
reemplazo usado por los perfiles legítimos (donde una repetición ocasional
no importa). Se implementó con un mezclado Fisher-Yates del espacio de
direcciones utilizables (1 a 254) para que la selección sea uniforme y sin
un orden artificial. Entra en pánico si se piden más de 254: es un error
de configuración de la campaña, no un caso a manejar en tiempo de
ejecución. Con `IPCount = 150`, queda holgadamente dentro del límite de un
solo /24.

**Sondas aisladas, no una sesión.** A diferencia de los generadores de
tráfico legítimo, cada IP participa con 1 a 3 intentos aislados repartidos
al azar en toda la ventana de la campaña (3 horas simuladas) — no hay una
"sesión" continua por IP, así que no se usa un reloj manual por IP; cada
timestamp se calcula directo como un desplazamiento aleatorio dentro de la
ventana, y el conjunto completo se ordena al final.

**Cada intento prueba, casi siempre, una cuenta distinta —
`AccountReuseProbability = 5%` en vez de 0%.** Una diversidad de cuentas
del 100% sería una señal demasiado limpia — una lista de credenciales
filtrada real suele reciclarse parcialmente entre bots. Se comprueba con
un test que el ratio de cuentas distintas sea alto (>80%), no exactamente
100%.

**Valores del generador (150 IPs, 1–3 intentos, ventana de 3 h, 1% de
éxito, 5% de reutilización de cuenta) son parámetros del dataset, no
umbrales de detección** — el motor define sus propios umbrales de forma
independiente de cómo se generó este tráfico; confundir "con qué
parámetros generé el ataque" con "con qué umbral lo voy a detectar" sería
circular.

### Verificación con ASN real: correlación de 30 IPs de Internet

Con el enriquecimiento real de ASN conectado (sección 7), se armó una
campaña de credential stuffing con 30 IPs públicas reales dentro de
`8.8.8.0/24` (Google, AS15169), 15 cuentas distintas, 84% de fallos. La
`Decision` final:

```json
{
  "entity_id": "network:asn:15169",
  "action": "CHALLENGE",
  "attack_vector": "credential_stuffing",
  "confidence_score": 0.52,
  "contributing_signals": [
    {"name": "distinct_ips_in_window", "value": 30, "weight": 0.25},
    {"name": "distinct_accounts_in_window", "value": 15, "weight": 0.25},
    {"name": "auth_attempts_in_window", "value": 76, "weight": 0.25},
    {"name": "failed_auth_ratio", "value": 0.84, "weight": 0.25}
  ]
}
```

**Hallazgo real durante la verificación, documentado por ser instructivo:**
el primer intento, con exactamente 20 IPs (el mínimo configurado en ese
momento) y sin pausa entre requests, no disparó — no por un bug, sino
porque, bajo una ráfaga rápida de 20 consultas casi simultáneas a un
servicio público gratuito, RIPEstat ocasionalmente tardó o falló para
alguna IP puntual (`distinctIPs` quedó en 19, no en 20, en esa corrida). El
detector se comportó exactamente como está diseñado: excluyó esa IP no
resuelta de la correlación en vez de arriesgar un grupo incompleto. La
solución no fue "arreglar un bug": fue dar margen real (30 IPs, una pausa
de 150 ms entre requests) para absorber la variabilidad inherente de
depender de un servicio de terceros en el camino síncrono de cada request.

### Calibración: de la configuración inicial a `CSw2`

**Ningún umbral final se eligió mirando la semilla de reporte (42).** Los
valores usados durante el desarrollo eran valores de prueba, elegidos para
poder calcularlos a mano y explícitamente documentados como no-finales. La
calibración real se hizo contra datasets de tuning (semillas 101/102/103)
separados del dataset de reporte, siguiendo el mismo criterio ya aplicado
al baseline de rate limiting (sección 10): calibrar mirando solo los datos
de tuning, y recién después correr, ya fijo, contra otros datos.

**Resultado inicial medido (baseline, configuración sin cambios).**
`credential_stuffing` resultó, junto con los otros dos detectores, el
componente más sólido y estable del baseline: recall 84%–98% en las
ratios de 10% y 30%, sin degradación al subir la proporción de tráfico
malicioso (a diferencia de `slow_scan`, sección 5), exactamente 1 campaña
detectada por escenario (confirmando que la correlación agrupaba por ASN,
no por IP), siempre dentro de su ventana de 30 minutos. RiskScore de 0 en
el 100% del tráfico legítimo (cero riesgo de falso positivo). No se
propuso ningún cambio para este detector en la primera pasada de
calibración.

**Hallazgo estructural: `credential_stuffing` casi nunca "gana" solo —
depende de `statistical_anomaly` como asistencia.** Un análisis posterior,
comparando qué detector produce cada mitigación evento por evento, mostró
que el gate propio de `credential_stuffing`, en los candidatos evaluados
en ese momento y en los tres seeds, nunca disparaba sin que
`statistical_anomaly` (sección 6) también lo hiciera: a 10% de tráfico
malicioso, el 100% de sus eventos mitigados dependían únicamente de
`statistical_anomaly`; a 30%, ~33% dependían solo de anomaly y ~67% tenían
a los dos disparando juntos, pero el propio gate de `credential_stuffing`
jamás disparaba en soledad. Causa más probable: `Window=30min` (la
ventana original del detector) es mucho más corta que la ventana de 3
horas en la que se genera la campaña — en cualquier ventana de 30 minutos,
las decenas de IPs atacantes rara vez se concentran lo suficiente como
para que `MinDistinctIPs` cruce por sí solo. La conclusión inicial de que
"credential stuffing funciona sólido, no necesita cambios" medía la
Decision final, no quién la producía — con esta evidencia, ese recall
resultaba en gran parte prestado de `statistical_anomaly`.

**Diagnóstico: ventana real vs. ground truth, con datos.** Se midió, para
cada campaña de las tres seeds de tuning, el máximo de cada señal del gate
observado en cualquier momento de la campaña, comparado contra los
thresholds vigentes (`MinDistinctIPs=20`, `MinDistinctAccounts=15`,
`MinAttempts=25`, `MinFailedRatio=0.60`). `FailedRatio` nunca resultó
limitante (siempre 1.00). A 30% de tráfico malicioso, ningún gate
resultaba limitante: el detector sí disparaba solo, alrededor del request
#25–42 de una campaña de 150–172 requests — la hipótesis de "la ventana es
el problema" no se sostenía ahí. A 10%, en cambio, los totales completos
de la campaña (19–20 IPs a lo largo de las 3 horas enteras) ya estaban
apenas en el umbral — ni siquiera una ventana que cubriera la campaña
completa habría garantizado cruzar `MinDistinctIPs=20` con margen, y
`MinDistinctAccounts`/`MinAttempts` también limitaban simultáneamente en 2
de 3 seeds.

**Verificación de sensibilidad a `Window`, antes de aprobar ningún
sweep.** Se pidió una corrección al diagnóstico anterior: `MinAttempts=25`
resultó ser un gate igual de central que `MinDistinctIPs` a 10%, algo que
el análisis previo no había señalado con el mismo peso. Se recalculó,
offline y sin tocar el detector de producción, el máximo *rolling* de las
cuatro señales del gate con `Window` en 30, 60 y 90 minutos, sobre los
mismos eventos de las tres campañas al 10%:

| Seed | Window | Max IPs (min 20) | Max Cuentas (min 15) | Max Attempts (min 25) | Max FailedRatio (min 0.60) |
|---|---|---|---|---|---|
| 101 | 30m | 9 | 10 | 11 | 1.00 |
| 101 | 60m | 14 | 17 | 18 | 1.00 |
| 101 | 90m | 16 | 23 | 24 | 1.00 |
| 102 | 30m | 12 | 15 | 15 | 1.00 |
| 102 | 60m | 16 | 23 | 23 | 1.00 |
| 102 | 90m | 18 | 30 | 30 | 1.00 |
| 103 | 30m | 13 | 13 | 14 | 1.00 |
| 103 | 60m | 19 | 21 | 22 | 1.00 |
| 103 | 90m | 19 | 27 | 28 | 1.00 |

Conclusión: ensanchar únicamente la ventana (aun a 90m) no alcanza —
`MinDistinctIPs` queda estructuralmente por debajo del umbral en los tres
seeds sin importar cuánto se ensanche dentro de lo razonable, y
`MinAttempts` sigue fallando en uno de tres seeds incluso a 90m. Hacía
falta combinar `Window` con una reducción de ambos `MinDistinctIPs` y
`MinAttempts`.

**Sweep de 5 candidatos (`CS0`–`CSw4`).**

| Candidato | Window | MinDistinctIPs | MinAttempts | MinDistinctAccounts | MinFailedRatio |
|---|---|---|---|---|---|
| `CS0-baseline` | 30m | 20 | 25 | 15 | 0.60 |
| `CSw1-window90` | 90m | 20 | 25 | 15 | 0.60 |
| `CSw2-window90-ips16` | 90m | 16 | 25 | 15 | 0.60 |
| `CSw3-window90-ips16-attempts24` | 90m | 16 | 24 | 15 | 0.60 |
| `CSw4-conservative` | 90m | 18 | 25 | 15 | 0.60 |

`FPR@0%` resultó idéntico en los 5 candidatos: en el dataset sintético, no
hay tráfico legítimo que se parezca lo suficiente a credential stuffing
(mismo ASN, mismo endpoint de auth, volumen alto) como para que bajar
estos umbrales disparara ningún falso positivo nuevo. **Esto se documentó
explícitamente como una limitación del dataset, no como garantía**: no
demuestra que estos umbrales sean seguros contra tráfico legítimo real de
alto volumen (por ejemplo, un servicio interno con reintentos
automáticos), solo que no rompen nada contra este generador concreto.

`BroadRecall@30%` mejoró de forma casi idéntica en los 4 candidatos con
`Window=90m` frente al baseline (0.7503→0.7647) — el salto lo produce
ensanchar la ventana, no los ajustes de `MinDistinctIPs`/`MinAttempts`
sobre ella. Donde sí hubo diferencia fue en `StrictRecall@30%` (BLOCK
puro): `CSw3` resultó el mejor (0.2615). A 10%, ningún candidato llegó a
detectar las tres campañas: `CSw1` (solo ventana) se quedó en 0/3, igual
que el baseline; `CSw2`/`CSw3`/`CSw4` llegaron a 2/3 — el seed 101 nunca se
detectó en ningún candidato, ni siquiera `CSw3` (cuyos umbrales coincidían
exactamente con los máximos observados para ese seed a 90m), porque el
máximo de cada señal puede ocurrir en instantes distintos de la campaña, y
el gate exige que las cuatro se cumplan simultáneamente en la misma
evaluación — "usar el mínimo de los máximos observados" resultó ser una
cota optimista, no una garantía.

**Decisión final: `CSw2` (Window=90 min, MinDistinctIPs=16, resto sin
cambios).** Se aprobó como configuración congelada para el resto de la
calibración. `CSw4` (el "conservador") lograba una detección eventual casi
igual con un umbral de IPs menos agresivo (18 en vez de 16); `CSw3` era
marginalmente mejor en cobertura y en velocidad de detección, pero con dos
umbrales llevados al mínimo observado, sin margen.

### Configuración final congelada

| Parámetro | Valor |
|---|---|
| Window | 90 min |
| MinDistinctIPs | 16 |
| MinDistinctAccounts | 15 (sin cambios) |
| MinAttempts | 25 (sin cambios) |
| MinFailedRatio | 0.60 (sin cambios) |
| ScoreFloor | sin cambios (nunca se tocó en ningún paso de la calibración) |

### Resultado en holdout: generalización y su límite

Con la configuración congelada, se corrió una única vez el conjunto de
holdout (semillas 201/202/203, nunca vistas durante la calibración).
`CS RecallDetector@10%` cayó de 0.2304 (tuning) a 0.1148 (holdout) — la
señal de generalización más débil de todo el proceso, coherente con que
`MinDistinctIPs=16`/`Window=90m` se habían derivado de los máximos
observados en solo 3 seeds de tuning, sin margen de sobra. `CS
RecallDetector@30%` generalizó, en cambio, casi perfecto (0.8515 en
tuning, 0.8517 en holdout). El máximo de `RiskScore` de
`credential_stuffing` sobre tráfico legítimo se mantuvo en 0.0000 tanto en
tuning como en holdout: los falsos BLOCK que sí aparecieron en holdout
(ver sección 8) no se originaron en este detector.

**Limitaciones conocidas, confirmadas con evidencia de holdout:**

- El dataset de 0% no genera tráfico legítimo de login de alto volumen
  desde un mismo ASN/patrón — la insensibilidad de `FPR@0%` a estos
  umbrales, observada durante el sweep, no debe leerse como garantía
  contra tráfico legítimo real de ese tipo.
- `CSw2` se calibró con el margen justo de solo 3 seeds de tuning, sin
  margen de sobra — confirmado por la caída a la mitad de
  `CS RecallDetector@10%` en holdout.

## 5. Slow Scan

### `internal/slowscan`: qué es y qué no es

**Problema.** Detectar escaneo/enumeración lenta de rutas HTTP — un
atacante que mantiene una tasa baja de requests a propósito, para evitar
un rate limiter, pero deja un patrón de exploración acumulado dentro de
una ventana. A diferencia de `credential_stuffing`, esta señal es por
entidad individual (IP y/o sesión), nunca correlacionada entre IPs — mismo
criterio que usa el generador de datos para producir este tráfico.

**Decisión — reutiliza `internal/profile.Store` en vez de duplicarlo.**
`profile.Metrics` ya cubre `Total`, `DistinctPaths` (`len(PathCounts)`),
`Status404`, `WithReferer`/`WithoutReferer`, por IP y por sesión, con
watermark y `Sweep` ya resueltos. `internal/slowscan` construye un
`*profile.Store` propio (no compartido con otros detectores) y lo
consulta. Lo único que `profile.Store` no puede dar es la popularidad de
una ruta *entre distintas entidades* (necesaria para `NovelPathRatio`) —
esa es la única pieza de estado genuinamente nueva de este detector
(`pathPopularity`), autocontenida por la misma razón que
`internal/credstuffing`: es una agregación distinta (por ruta, no por
IP/sesión).

### Las cinco señales del gate

**Entropía de Shannon normalizada.** `H = -Σp_i·log2(p_i)` sobre la
distribución de `PathCounts`, dividida por `log2(DistinctPaths)` para que
perfiles con distinta cantidad de rutas sean comparables con el mismo
umbral (`RouteEntropy=0` si `DistinctPaths≤1`, por definición — sin
diversidad que medir). Confirmado con ejemplos calculados a mano: 4 rutas
con 1 visita cada una → `1.0` (máxima diversidad); 4 rutas muy
concentradas (`17,1,1,1` sobre 20) → `≈0.424`.

**Novedad de rutas: rareza poblacional, no un catálogo externo.** No
existe ninguna fuente de "rutas reales de la aplicación" disponible para
el motor, y usar la lista de rutas sensibles del generador de datos sería
trampa (es literalmente el ground truth del generador, y el motor no
puede importarlo). La opción mínima técnicamente correcta con los datos
disponibles: cuántas IPs distintas, en todo el tráfico que este detector
observó, pidieron cada ruta dentro de la ventana (`pathPopularity`, con el
mismo mecanismo de watermark de la sección 3). `NovelPathRatio` = fracción
de las rutas distintas de la entidad cuyo conteo global de visitantes es
`≤ MaxVisitorsForNovelPath`.

**Gate conjuntivo de cinco condiciones — `WithoutRefererRatio`
deliberadamente afuera.** `Triggered` exige `TotalRequests`,
`DistinctPaths`, `NotFoundRatio`, `RouteEntropy` y `NovelPathRatio` todos a
la vez por encima de su umbral. `WithoutRefererRatio` nunca es parte del
gate — solo aporta al `RiskScore`, ponderado. Así, la ausencia de Referer,
sea 0% o 100%, no puede por sí sola cambiar `Triggered`, porque ni siquiera
es una de las condiciones. El gate se verificó contra cada falso positivo
candidato: crawler legítimo y SPA (`NotFoundRatio` bajo — las rutas
existen, dan 200); cliente API sin Referer con navegación estable
(`DistinctPaths`/`RouteEntropy` bajos — pocos endpoints fijos repetidos);
enlaces rotos ocasionales y tráfico normal con algún 404 (`DistinctPaths`
bajo o el volumen de éxitos diluye el ratio); health checks (una sola
ruta repetida, `RouteEntropy=0`).

### IP y sesión: evaluar siempre las dos

**Corrección de diseño aplicada durante la revisión.** El diseño original
evaluaba por sesión cuando existía y por IP solo como respaldo — con un
hueco: un atacante que rota `session_id` cada pocos requests mantiene cada
sesión individual por debajo de los umbrales, mientras la IP agregada sí
muestra el patrón completo, y ese diseño nunca llegaba a mirarla.

**Corrección.** `Evaluate` calcula siempre el candidato por IP y, si
`e.SessionID != ""`, también el candidato por sesión, y devuelve como
máximo un único `Finding`: si las dos dispararon, gana la de mayor
`RiskScore` (en empate exacto, gana sesión, por ser la entidad más
específica — evita atribuir el hallazgo a todo un NAT cuando alcanza con
señalar la sesión concreta); si solo una disparó, esa; si ninguna, vacío.

**Por qué evaluar la IP siempre no reintroduce el falso positivo del
NAT.** A la IP se le aplica el mismo gate completo de cinco condiciones,
no una versión relajada. Un NAT de oficina con varias sesiones legítimas,
agregado a nivel IP, tiene muchas rutas distintas — pero son rutas reales
(`NotFoundRatio` bajo), así que nunca cruza esa condición, sin importar
cuánta diversidad sume el NAT. El escáner que rota sesiones sí cruza esa
misma condición a nivel IP, porque sigue pidiendo rutas del wordlist
(404). Es el mismo gate el que distingue ambos casos, no una regla
especial para NAT.

**Limitación honesta, documentada, no resuelta.** Si una IP tiene, a la
vez, tráfico legítimo de un NAT y un atacante real enumerando rutas, el
`Finding` a nivel IP puede terminar asociado también a algún evento de un
usuario legítimo de esa misma IP — mismo trade-off ya aceptado para
cualquier señal a nivel IP. Lo que esta solución sí evita es el falso
positivo cuando nadie malicioso está presente.

**Deuda documentada, resuelta después (sección 1).** `finding.Finding`
inicialmente no tenía ningún campo estructurado para indicar qué entidad
(IP o sesión, y cuál) originó un hallazgo — esa información solo vivía, en
texto libre, dentro de `Explanation`. Se anotó explícitamente en el código
como deuda a resolver cuando `engine.Decider` la necesitara de verdad, lo
que ocurrió al construir `BehavioralDecider` (sección 1).

### `RiskScore` y generación de tráfico de ataque

**`RiskScore`: mismo mecanismo de piso que `credential_stuffing`.** Seis
componentes (los cinco del gate + `WithoutRefererRatio`, que solo aporta
al score), combinados en un promedio ponderado con el mismo piso
`ScoreFloor ∈ (0,1)` estricto.

**Escaneo lento: rutas mezcladas, no 100% desconocidas.** El 15%
(`ValidPathProbability`) de los requests del escáner apunta a una ruta
real de la aplicación (tomada del perfil de navegación legítima, no
inventada aparte) en lugar de una ruta del wordlist de rutas sensibles
(verificado por test para que nunca se superponga con ninguna ruta de los
perfiles legítimos). Sobre esas rutas válidas, ~20% lleva parámetros de
query fuzzeados (solo nombres, nunca valores — misma regla de privacidad
del contrato de eventos).

### Calibración: de la configuración inicial a `S3`

**Resultado inicial medido (baseline).** `recall_slow_scan` cayó fuerte al
subir la proporción de tráfico malicioso de 10% a 30% (0.890→0.254,
0.847→0.436, 0.812→0.225 entre las tres semillas), mientras que
`recall_credential_stuffing` se mantuvo estable. La causa, visible en el
detection delay: a 30% hay 9 campañas de escáner en vez de 2 (el generador
reparte el mismo presupuesto de tráfico malicioso entre más escáneres),
así que cada campaña individual es más chica, y como el gate exige un
`MinRequests` (entre otras condiciones) antes de disparar, una porción más
grande de cada campaña más chica ocurre necesariamente antes de cruzar ese
piso. La detección "eventual" de la campaña se mantuvo alta (88%–100%) —
el detector casi siempre atrapaba al escáner tarde o temprano — pero el
recall a nivel de request, la métrica principal, caía correctamente y sin
disimularlo.

**Diagnóstico con datos reales: `MinRequests` no es el problema a 30%;
`NovelPathRatio` sí.** A 10% (6 campañas), el 100% se detectaba, todas
exactamente en el request #15, con `TotalRequests(14<15)` como única
condición limitante justo antes — las otras cuatro condiciones ya estaban
satisfechas mucho antes; `MinRequests` nunca era un problema real ahí, era
solo el último en cruzar. A 30% (27 campañas), usando el disparo propio
del gate (no la Decision final combinada), solo 13 de 27 campañas (48%)
cruzaban el gate alguna vez; de las 14 que nunca lo cruzaban, las 14
tenían `NovelPathRatio` como única condición limitante, nunca
`TotalRequests` — el tamaño de campaña a 30% (min=20 p50=44 max=60) era
prácticamente el mismo que a 10% (mediana 44 vs 45): la degradación no era
porque las campañas fueran más chicas.

**Mecanismo, verificado contra el código real del generador.** Cada ruta
del escáner se elige de un vocabulario compartido de solo 30 rutas
sensibles — el mismo para las 2 campañas de 10% y las 9 de 30%. Con 9
escáneres independientes en vez de 2, sorteando de las mismas 30 rutas, es
mucho más probable que 3 o más IPs de escáneres distintos visiten la misma
ruta dentro de la ventana — y `MaxVisitorsForNovelPath=2` hace que esa
ruta deje de contarse como "novel" para ninguno de ellos, aunque sea
comportamiento de escaneo genuino. No era "más fragmentación de ataque",
era contaminación cruzada del índice de popularidad de rutas entre
campañas simultáneas, agravada por que el pool de rutas nunca crecía
aunque hubiera más atacantes.

**Sweep de 4 candidatos (`S0`–`S3`), ninguno cambia `MinRequests`** (se
confirmó que no era el gate limitante a ninguna ratio):

| Candidato | FPR@0% | BroadRecall@30% | SSRecall@30% | EventualDet@30% (gate propio) |
|---|---|---|---|---|
| S0 baseline | 0.0472 | 0.4940 | 0.3050 | 0.4815 |
| S1 maxvisitors-3 (`MaxVisitorsForNovelPath`: 2→3) | 0.0472 (=) | 0.6456 | 0.5238 | 0.7407 |
| S2 novelratio-035 (`MinNovelPathRatio`: 0.50→0.35) | 0.0472 (=) | 0.5566 | 0.3954 | 0.5926 |
| S3 ambos combinados | 0.0472 (=) | 0.6757 | 0.5669 | 0.8519 |

`FPR@0%` y todo `@10%` quedaron idénticos en los 4 candidatos, en ningún
seed — exactamente lo que predecía el diagnóstico (`slow_scan` tiene
RiskScore=0 en el 100% del tráfico legítimo; a 10% las 2 campañas por seed
ya se detectan por `MinRequests`, nunca por `NovelPathRatio`). El tamaño
de la mejora fue enteramente de cobertura (más campañas cruzan el gate
alguna vez), no de velocidad de detección.

**Decisión final: `S3` (`MaxVisitorsForNovelPath=3` + `MinNovelPathRatio=0.35`
combinados).** Domina a S1 y S2 en todos los ejes medidos — mismo FPR@0%
(sin cambio), mismo comportamiento @10%, mejor recall/detección eventual
@30% de los cuatro (0.676 / 0.567 / 0.852) — sin ningún trade-off
identificado. S1 era la alternativa más simple (un solo parámetro) si se
hubiera preferido un cambio más chico, pero S3 no costaba nada adicional
sobre S1.

### Configuración final congelada

| Parámetro | Valor |
|---|---|
| MaxVisitorsForNovelPath | 3 |
| MinNovelPathRatio | 0.35 |
| Resto (incluido MinRequests) | sin cambios |
| ScoreFloor | sin cambios |

### Resultado en holdout

`SlowScan RecallDetector` generalizó razonablemente: 0.7045 en tuning,
0.6298 en holdout a 10%; 0.4758 en tuning, 0.5577 en holdout a 30%
(mejoró). Ninguna señal de overfitting específica de este detector se
observó en holdout — a diferencia de `credential_stuffing` a 10% (sección
4).

## 6. Detección estadística de anomalías

### `internal/anomaly`: qué es y qué no es

**Problema.** El challenge pedía incluir un modelo de detección de
anomalías estadístico o de ML, distinto de un conjunto de reglas.

**Decisión.** Un detector genuinamente estadístico: media/varianza
calculadas online con el algoritmo de Welford, z-scores unilaterales, y un
único umbral sobre un score combinado — a diferencia de
`credstuffing`/`slowscan`, que exigen varias señales crudas cruzando sus
propios umbrales a la vez. Esto justifica de forma técnicamente correcta
la afirmación de que el motor incluye un modelo de detección de anomalías
estadístico online, basado en media/varianza en ejecución y desviaciones
estandarizadas (z-scores).

**Motivo — alternativas descartadas.** Sin Isolation Forest, sin
One-Class SVM, sin autoencoders, sin dependencias de Python — se
descartaron explícitamente por agregar complejidad real sin necesidad
concreta para este prototipo.

**Modelo.** Welford (media, M2, varianza = M2/(n-1)) + z-score unilateral
(`z = max(0, (x-mean)/stddev)`, apropiado porque las cinco features
elegidas son todas "más alto = más sospechoso" en este dominio).

### Features y población

**Features — todas ratios derivados de `profile.Metrics`, nunca conteos
crudos:** `NotFoundRatio`, `FailedAuthRatio`, `PathDiversityRatio`
(`len(PathCounts)/Total`), `WithoutRefererRatio`, `AccountDiversityRatio`
(`DistinctAccounts/Total` — señal distinta de la correlación entre IPs que
ya cubre `credstuffing`: acá mide cuántas cuentas distintas probó una sola
entidad por su cuenta). Excluidas, con motivo: `Total` crudo (ver
limitación 2 más abajo), `WithReferer` (complemento exacto de
`WithoutRefererRatio`, no suma información), `DistinctSessions` (solo
tiene sentido claro por IP, no por sesión, complejidad no justificada).

**Población: global, no por IP/sesión — analizado y justificado.** Un
modelo por entidad nunca calentaría con el propio patrón de credential
stuffing distribuido de este proyecto (1-3 requests por IP en total) —
sería ciego exactamente al ataque que el challenge pide detectar. Un
baseline global, alimentado por el snapshot de features de cada entidad
evaluada, resuelve esto: una IP nueva, con una sola observación, ya se
puede puntuar contra "cómo se ve normalmente un perfil", sin esperar su
propia historia. IP y sesión comparten el mismo baseline — un
`NotFoundRatio` significa lo mismo sin importar el tipo de entidad que lo
produjo.

**Reutiliza `internal/profile.Store`, con un `*Store` privado** — mismo
criterio, mismo costo de memoria aceptado, que `internal/slowscan`: el
mismo evento queda retenido tres veces, una por cada detector, acotado por
la ventana de cada uno — trivial a esta escala. El baseline de Welford en
sí (un puñado de escalares) nunca crece con la cantidad de entidades — a
diferencia de `profile.Store`, no necesita `Sweep` propio.

**Dos limitaciones documentadas explícitamente, desde el diseño:**

1. El baseline global mezcla poblaciones con formas de tráfico
   naturalmente distintas (un cliente de API y un navegador humano no son
   "iguales" solo porque ninguno es sospechoso), y una sola muestra por
   evento evaluado significa que una entidad muy activa aporta muchas
   muestras correlacionadas entre sí, pudiendo sesgar el baseline hacia su
   propia forma de tráfico.
2. Al excluir el volumen crudo (`Total`) de las features, este detector se
   enfoca en anomalías de la forma/proporciones del comportamiento — no
   pretende detectar por sí solo un incremento puramente volumétrico; eso
   ya es responsabilidad de `credstuffing`/`slowscan`.

### Warm-up, orden de actualización y protección contra varianza cero

**Warm-up y orden score-antes-actualizar, resuelto como una excepción
documentada al patrón del proyecto.** `n < MinSamples` → `Evaluate`
siempre `Finding{}`, sin importar el valor. `Observe(e)` en este detector
solo alimenta el `profile.Store` privado; el baseline de Welford se
actualiza dentro de `Evaluate`, después de puntuar contra una foto tomada
al principio (antes de que nada la modifique) — así el propio punto
anómalo nunca reduce artificialmente su propio z-score por haberse
promediado a sí mismo antes de calcularlo. Es una excepción documentada al
patrón "`Observe` muta, `Evaluate` solo lee" que sí siguen
`credstuffing`/`slowscan` — el contrato público no cambia, el detalle es
interno.

**Varianza cero → z=0, nunca NaN/Inf.** No se puede afirmar "cuántos
desvíos estándar" de algo que todavía no tiene desvío — se trata esa
feature como no informativa esa ronda, la opción conservadora.

**Anti-contaminación del baseline (baseline poisoning), analizado y
resuelto con la opción mínima.** Después del warm-up, una muestra con
`Triggered=true` no se agrega al baseline — solo lo "normal" actualiza la
media/varianza. Durante el warm-up, toda muestra se agrega sin excepción
(no hay juicio de "anómalo" todavía, y excluir desde el arranque podría
dejar el baseline sin calentar nunca si el tráfico inicial ya es
mayormente ataque) — **limitación conocida, documentada, no resuelta**: es
un límite de cualquier baseline aprendido sin supervisión.

**Combinación de z-scores en `RiskScore`, sin sumar z crudos.** Cada `z_i`
se normaliza a `[0,1)` con la misma familia de heurística asintótica ya
usada en los otros detectores, adaptada a un z-score:
`component = z/(z+ZSaturation)`. Los componentes se combinan en un
promedio ponderado. `Triggered` es un único umbral sobre ese score
combinado (`TriggerThreshold`), no un gate conjuntivo de señales — la
diferencia de fondo con `credstuffing`/`slowscan`. `RiskScore = ScoreFloor
+ (1-ScoreFloor)*combined`, mismo mecanismo de piso, acá una defensa
adicional (`TriggerThreshold > 0` ya garantiza `RiskScore > 0` en el borde
exacto).

**`AttackVector = unknown`, siempre.** El evaluador (sección 10) ya
excluye `AttackVectorUnknown` del balde "Incorrecto" y lo cuenta aparte
como "Desconocido". Inventar un vector nuevo (`"anomaly"`) habría roto
esto: como el ground truth del evaluador solo conoce
`legit`/`credential_stuffing`/`slow_scan`, cualquier decisión con un
vector nuevo caería siempre en "Incorrecto" en esa comparación,
penalizando injustamente a un detector que está siendo honesto sobre sus
límites — `unknown` no es una limitación de este diseño, es la respuesta
técnicamente correcta dado cómo funciona el evaluador.

**`TriggerThreshold` deliberadamente bajo (0.15 en producción).** Con las
cinco features pesadas por igual, una desviación clara en una sola de
ellas nunca puede empujar el score combinado mucho más allá de ~0.2 (las
otras cuatro, cerca de su media, aportan ~0 al promedio) — un
`TriggerThreshold` alto haría que este detector nunca disparara en la
práctica. El primer intento de test de "desviación clara dispara" usaba
`TriggerThreshold=0.5` y fallaba, no por un error del detector sino por
esta misma razón matemática — se bajó a 0.1 en los tests y a 0.15 en
producción, con margen.

**Verificación manual real con `curl`.** Se calentó el baseline con 60
requests normales (10% de 404, seis IPs distintas), y una entidad nueva
mandó 20 requests a la misma ruta (para no cruzar el gate de `slow_scan`,
que exige diversidad de rutas) con 90% de 404 — el motor real respondió
`CHALLENGE` con `attack_vector:"unknown"` y `not_found_ratio_z:29.4`,
confirmando que el detector estadístico, y no los otros dos, fue quien
disparó.

### Hallazgo durante la verificación de observabilidad: dos límites genuinos, no teóricos

Al intentar forzar este detector con tráfico real durante la verificación
del stack de observabilidad (sección 9), costó mucho más de lo esperado, y
expuso dos límites genuinos del diseño, no solo teóricos:

1. Un baseline con cero varianza real (todas las muestras idénticas, por
   ejemplo siempre con `Referer`) desactiva por completo el z-score de esa
   feature — a propósito, para no dividir por (casi) cero y explotar. Es
   correcto y deseable, pero significa que un dataset sintético demasiado
   homogéneo nunca puede disparar este detector, sin importar cuán extrema
   sea la desviación — hace falta variabilidad real en el baseline
   primero.
2. Como el baseline es global y las muestras que no disparan se siguen
   agregando, varios intentos fallidos consecutivos, sobre el mismo
   proceso corriendo, terminaron contaminando su propio baseline con las
   mismas muestras "anómalas" que no habían disparado — inflando la
   varianza aprendida y haciendo cada intento posterior más difícil, no
   más fácil. Reiniciar el proceso (el baseline en memoria se pierde al
   reiniciar) y hacer un único intento bien calculado fue lo que
   finalmente funcionó.

Ninguno de los dos es un bug: son la consecuencia directa, observada en la
práctica, de un diseño ya documentado (baseline global, z-score protegido
contra varianza cero).

### Calibración: de la configuración inicial a `A3`

**Falsos positivos confirmados explícitamente, no por eliminación.** En el
baseline, los falsos positivos bajo política amplia en el escenario de 0%
de tráfico malicioso (41 a 76 por corrida, FPR 3.5%–6.7%) resultaron, por
eliminación estructural (ningún gate conjuntivo de los otros dos
detectores puede dispararse sobre tráfico 100% legítimo), atribuibles al
100% a `statistical_anomaly`. Se confirmó con datos, no solo por
descarte: sobre 164 casos analizados, `PrincipalDetectorConfirmed=true`
en el 100% (0 excepciones) — los otros dos detectores nunca disparaban en
ninguno.

**El corte matemático se confirma casi exacto con datos reales.** El score
combinado máximo entre los ALLOW legítimos fue 0.3749; el mínimo entre los
CHALLENGE fue 0.3758 — el límite teórico (ScoreFloor=0.20,
ChallengeThreshold=0.50 → combined≈0.375) se verificó en la práctica, casi
al cuarto decimal. **Consecuencia para elegir el parámetro relevante:**
`TriggerThreshold` (0.15) estaba muy por debajo de ese ~0.375 — moverlo
dentro de {0.10, 0.15, 0.20} no podía mover ni un solo evento de estos 164
de CHALLENGE a ALLOW. `ZSaturation` sí era relevante, pero de forma
desigual: recalculado a mano el primer falso positivo de la tabla
analizada, con `ZSaturation=3` el combined bajaba de 0.5527 a 0.4884
(seguía disparando), con `ZSaturation=1` subía a 0.6448 (empeoraba). Para
casos con z extremos (hasta 74), el componente ya estaba saturado cerca de
1 para cualquier `ZSaturation∈{1,2,3}` — subir `ZSaturation` ayudaba a los
casos borderline pero no podía arreglar los más extremos por sí solo.

**Hallazgo adicional, no buscado pero relevante.** En casi todas las filas
analizadas, `failed_auth_ratio_z` y `account_diversity_ratio_z` resultaron
idénticos. Son dos features distintas en el modelo, pero en la población
legítima concreta analizada (tráfico tipo API client) estaban
perfectamente correlacionadas — el modelo las contaba dos veces como si
fueran evidencia independiente, inflando el combined score más de lo que
un observador esperaría de "5 señales independientes". No se propuso
tocar pesos por esto en ese momento (fuera del alcance acordado en esa
etapa), pero explica por qué el combined score de estos falsos positivos
era más alto de lo que la intuición sobre 5 features independientes
sugeriría.

**Sweep de 6 candidatos (`A0`–`A5`):**

| Candidato | FP@0% (avg) | FPR@0% (avg) | BroadRecall@10%(avg) | BroadRecall@30%(avg) | Recall CS@10% (min–max entre seeds) |
|---|---|---|---|---|---|
| A0 baseline | 54.7 | 0.0472 | 0.8752 | 0.4940 | 0.842–0.977 |
| A1 z3 (ZSaturation 2→1) | 26.0 | 0.0225 | 0.7321 | 0.3722 | 0.553–0.954 |
| A2 trigger020 (TriggerThreshold 0.15→0.20) | 40.3 | 0.0350 | 0.8205 | 0.4418 | 0.842–0.977 (≈ igual) |
| A3 account-weight05 (AccountDiversityWeight→0.5) | 44.3 | 0.0384 | 0.9230 | 0.6717 | 0.737–0.954 |
| A4 z3+weight05 | 19.0 | 0.0164 | 0.7386 | 0.3705 | 0.342–0.930 |
| A5 z3+trigger020 | 12.0 | 0.0104 | 0.7297 | 0.3722 | 0.526–0.954 |

**Hallazgo central, en los tres seeds y los cinco candidatos, sin
excepción:** "dejó de Triggered" fue siempre 0 — ningún candidato hace que
una evaluación de anomaly deje de disparar del todo. El 100% de la
reducción de falsos positivos venía de "sigue Triggered, pero la Action
final pasa a ALLOW" (el RiskScore baja de 0.50, no de 0.20) — confirma
exactamente el mecanismo ya identificado arriba (el límite real es
ScoreFloor+Challenge≈0.375 en espacio de combined, muy por encima de
cualquier `TriggerThreshold` del grid).

**Hallazgo no anticipado (negativo): `ZSaturation=3` reduce FP con fuerza,
pero daña recall de forma inestable entre seeds.** El caso más claro:
`Recall credential_stuffing@10%` del seed 101 cae de 0.842 (baseline) a
0.553 en A1 y a 0.342 en A4. Esto ocurre porque `statistical_anomaly`,
aunque nunca sea "el" vector atribuido, contribuye recall extra sobre
eventos de credential_stuffing/slow_scan (los marca como positivos incluso
antes de que el gate propio de esos detectores cruce) — bajar la
sensibilidad general de anomaly le quita esa cobertura adicional, con un
efecto desigual entre seeds.

**Hallazgo no anticipado (positivo): `AccountDiversityWeight=0.5` (A3)
mejora recall en vez de sacrificarlo.** `BroadRecall@30%` sube de 0.494 a
0.672 — la reducción del peso, al reducir también el denominador de la
normalización, redistribuye sensibilidad hacia el resto de las features en
vez de solo apagar la que correlaciona con `failed_auth` (el hallazgo
documentado arriba). FP baja menos (19% vs. el 52% de A1) pero sin ningún
costo de recall — de hecho con una ganancia.

**Decisión final: `A3` (`AccountDiversityWeight=0.5` únicamente).** Es el
único candidato que mejora recall en vez de dañarlo, con una reducción de
FP real aunque modesta, y con estabilidad entre seeds razonable. Se
descartaron `A1`/`A4`/`A5` pese a su mayor reducción de FP (hasta 78% en
A5) porque dañaban recall de forma seria e irregular entre seeds — la
caída de recall de `credential_stuffing` a 0.34–0.55 en algunos seeds se
consideró un costo demasiado alto e impredecible para una mejora de FP que,
de todos modos, no llegaba a eliminar el problema. `A2` quedó como
alternativa conservadora (FP baja 26% con daño de recall mínimo, pero
menos ambicioso).

### Configuración final congelada

| Parámetro | Valor |
|---|---|
| AccountDiversityWeight | 0.5 |
| Resto | default |
| ScoreFloor | sin cambios |

### Regla de atribución: por qué `statistical_anomaly` deja de "ganar" el vector

**Problema detectado después de congelar Policy.** `statistical_anomaly`,
al tener a veces el mayor `RiskScore`, podía convertirse en principal y
dejar `attack_vector=unknown` en la Decision aunque `credential_stuffing`
o `slow_scan` también hubieran disparado — una atribución engañosa: "no
sabemos qué es esto" cuando sí había una hipótesis específica activa.

**Decisión — se separan dos preguntas que antes resolvía el mismo
Finding:**

1. **Action/ConfidenceScore** ("qué tan riesgoso es"): sigue siendo el
   mayor RiskScore entre todos los Triggered, sin importar qué detector lo
   produjo.
2. **AttackVector/EntityID/ContributingSignals/Explanation principal**
   ("de qué ataque se trata"): si cualquier detector específico
   (`credential_stuffing`/`slow_scan`) disparó, se usa el de mayor
   RiskScore entre esos — `statistical_anomaly` nunca es candidato en ese
   caso, sin importar cuánto mayor sea su propio score. Solo cuando ningún
   específico disparó se usa `statistical_anomaly` (que ya reporta
   `unknown` como su propio AttackVector, no una regla especial de esta
   función).

El desempate determinista entre detectores específicos
(`credential_stuffing` gana un empate exacto contra `slow_scan`) se
mantuvo sin cambios.

**Verificación empírica de que el cambio no altera ninguna métrica de
acción en el dataset de tuning.** Se re-corrió el sweep completo de
Policy con el código corregido y se comparó el reporte resultante contra
una copia guardada de antes del cambio: la diferencia fue completamente
vacía — cero diferencias en ningún número, incluidos TP/FP/TN/FN,
Precision, Recall, FPR, FNR, F1. Explicación: la RiskScore mediana de
`credential_stuffing` sobre tráfico malicioso (~0.77) ya solía ser más
alta que la de `statistical_anomaly` (~0.50) en los eventos donde ambos
coincidían, así que `credential_stuffing` ya ganaba el desempate por score
en la mayoría de esos casos, incluso con la regla anterior — la corrección
de atribución no cambió nada medible en ESTE dataset concreto porque casi
nunca se daba la condición que el cambio corrige, pero un test de
integración sintético prueba explícitamente que si esa condición sí se da,
la corrección actúa como se espera.

### Resultado en holdout: el efecto de escala del baseline global

**El baseline de `statistical_anomaly` es global — confirmado como causa
directa de los 3 falsos BLOCK en holdout.** El máximo de `RiskScore` de
este detector sobre tráfico legítimo llegó a 0.7722 en holdout, por
encima de `BlockThreshold=0.75` — mientras que en tuning ese máximo nunca
superó 0.6998–0.7079. `credential_stuffing` y `slow_scan` se mantuvieron
en 0.0000 de máximo sobre tráfico legítimo también en holdout: los falsos
BLOCK no vinieron de los detectores específicos, vinieron enteramente de
`statistical_anomaly`, cuyo baseline global ocasionalmente ve una sesión
legítima lo bastante inusual (dentro de ~10884 eventos legítimos de
holdout) como para cruzar el umbral — un efecto estadístico esperable a
esa escala con un baseline global, no un error de configuración. Coincide
exactamente con la limitación de diseño ya documentada ("el baseline
anomaly es global"), manifestándose con datos reales por primera vez. Más
detalle sobre este hallazgo y sus consecuencias para Policy en la sección
8.

## 7. Enriquecimiento ASN

### `internal/asn`: qué es y qué no es

**Problema.** El challenge exige enriquecer IPs con al menos una fuente
pública/gratuita de ASN, y `internal/credstuffing` necesitaba un
`NetworkResolver` real para dejar de depender del placeholder inerte
(sección 1).

**Decisión.** `internal/credstuffing` no cambió ni una línea: la interfaz
`NetworkResolver` (`Resolve(ip netip.Addr) (string, bool)`) ya existía
desde el diseño original del detector, y `asn.Resolver` la satisface por
tipado estructural de Go — `internal/asn` no importa
`internal/credstuffing` para nada, el detector nunca sabe qué proveedor
hay detrás.

**Fuente: RIPEstat (RIPE NCC), `network-info`.** Gratuita, sin API key —
nada que hardcodear como secreto. Es una fuente apropiada para este
challenge/prototipo (RIPE NCC es uno de los cinco *Regional Internet
Registries* reales, no un scraper de terceros), pero **no se presenta como
el proveedor definitivo de un despliegue de producción**: sus términos de
uso actuales restringen determinados usos comerciales sin permiso
explícito. Se agregó el parámetro `sourceapp` (configurable, fijo por
defecto al nombre del proyecto) en cada consulta, siguiendo la propia guía
de uso de RIPEstat, para que un uso regular/automatizado quede
identificable, no anónimo.

### Ajustes de diseño sobre la integración

**Política conservadora ante múltiples ASN, sin elegir arbitrariamente.**
`network-info` puede devolver más de un ASN para una IP (multi-homing). En
vez de tomar el primero (inventaría una correlación de grupo sin
garantía), la regla es:

```
0 ASN         → ("", false)
exactamente 1 → ("asn:<número>", true)
más de 1      → ("", false)
```

**El timeout acota todo `Resolve`, incluida la espera de capacidad.**
`Resolve` arma un único `context.WithTimeout` al principio, y lo usa tanto
para esperar un cupo del semáforo de concurrencia como para la llamada
HTTP en sí. Si el plazo se consume esperando capacidad, devuelve
`("", false)` sin haber llegado a consultar al proveedor — nunca una
espera sin límite antes del timeout configurado.

**Documentado explícitamente: el lookup remoto síncrono es aceptable para
el prototipo, no sería el diseño de producción.** `Resolve` se llama de
forma síncrona dentro de `credstuffing.Detector.Observe`, en el camino de
cada request de `POST /v1/events`. Para este prototipo, el timeout corto +
el caché agresivo alcanzan. **Limitación conocida, no resuelta acá:** para
tráfico masivo con muchas IPs nunca vistas, el diseño correcto sería un
enriquecimiento asíncrono/diferido que no bloquee la decisión inicial.

**Caché positivo y negativo, con TTL — mismo patrón `Sweep` que el resto
del proyecto.** Un mapa `IP → {grupo, ok, vencimiento}` protegido por
mutex; TTL largo para aciertos (`SuccessTTL`, un ASN real cambia rara vez)
y corto para fallos (`FailureTTL`, caché negativo: no reintenta en cada
request contra un proveedor caído, pero sí reintenta pronto cuando
vuelva). `Resolver.Sweep(now)` limpia entradas vencidas — no conectado a
ningún scheduler, mismo criterio ya documentado en otros componentes con
estado (secciones 3 y 4).

**Límite de concurrencia propio.** Un semáforo (`chan struct{}`) acota
cuántas consultas HTTP puede haber en vuelo a la vez — protección hacia el
servicio público gratuito y contra una ráfaga de IPs nunca vistas. **Sin
deduplicación de ráfagas** (tipo `singleflight`): bajo una ráfaga de la
misma IP nunca vista podrían salir 2-3 llamadas redundantes antes de que
la primera cachee — limitación aceptada y documentada, no una dependencia
externa nueva para un caso de baja probabilidad a esta escala.

**Reutiliza `event.Clock`, no otra interfaz de reloj más.** El TTL del
caché usa `event.Clock`/`event.SystemClock`/`event.ManualClock` (sección
2) — mismo criterio de no duplicar abstracciones ya disponibles en el
proyecto.

### Limitación con el dataset sintético del propio proyecto

**RFC 5737 no se puede enriquecer de verdad, verificado, no solo
mencionado.** El generador de datos usa deliberadamente rangos de
documentación (`192.0.2.0/24`, etc.). Ningún proveedor real de ASN tiene
datos para esos rangos — contra los datasets sintéticos del proyecto, el
resolver real se comporta exactamente igual que el placeholder inerte
(siempre `ok=false`). No es un bug: es la consecuencia correcta de una
decisión de diseño ya tomada al construir el generador de tráfico (sección
10). Por eso toda verificación manual con datos reales de este componente
usa IPs públicas reales, nunca el dataset sintético.

### Configuración y operación

**`cmd/engine`: `--asn-provider`, default seguro.** `"none"` (default:
`credstuffing.UnavailableNetworkResolver{}`, nunca hace tráfico de salida
a menos que se pida explícitamente — importante en un contexto de
seguridad y para entornos restringidos/offline) o `"ripestat"`
(`internal/asn.Resolver` real). Más `--asn-timeout` y `--asn-cache-ttl`.
Ningún secreto que configurar — RIPEstat no los necesita.

### Verificación

**Tests.** Contra un `httptest.Server` fake — ninguno depende de Internet
real: validación de configuración; parseo exitoso (con y sin el prefijo
`"AS"`); el caso multi-ASN; cero ASN; JSON malformado; `status` HTTP
distinto de 200; `status` de RIPEstat distinto de `"ok"`; timeout con el
proveedor real colgado; timeout consumido esperando capacidad sin llegar a
llamar al proveedor (armado ocupando el único cupo directamente sobre el
campo interno del semáforo, desde el mismo paquete, para que el test sea
determinista — el primer intento de este test sí tenía una carrera de
tiempos entre dos timeouts y falló intermitentemente, se corrigió antes de
dejarlo); caché positivo evita una segunda llamada; TTL positivo vence y
vuelve a consultar; TTL negativo (más corto) vence y reintenta; `Sweep`
elimina solo lo vencido; límite de concurrencia nunca superado (verificado
contando conexiones simultáneas reales al fake server); concurrencia
general con `go test -race`.

**Verificación manual real, ejecutada con IPs públicas reales** (requiere
acceso real a Internet, a diferencia de todo lo demás en el proyecto): ver
el resultado completo de la campaña de 30 IPs de Google (AS15169) en la
sección 4.

## 8. Política de decisión

### El contrato de `Decision`

**Problema.** Hacía falta un tipo simétrico a `Event` para representar la
salida del motor, que sirviera tanto al evaluador (sección 10) como,
después, al log de auditoría completo que pide el PDF del challenge.

**Decisión — `Decision` en `internal/decision`.** Contiene
`request_id`, `timestamp`, `entity_id`, `action`, `confidence_score` y
`attack_vector` como núcleo, más los campos de auditoría agregados
después: `ContributingSignal` (`name`, `value`, `weight`),
`ContributingSignals`, `Explanation` (la explicación determinista,
calculada por reglas, síncrona) y `LLMExplanation` (puntero a string,
porque hace falta distinguir tres estados: "esta decisión no usa LLM", "el
LLM todavía no respondió" y "el LLM respondió esto, incluso si fue un
string vacío"). Es un único tipo — el evaluador simplemente ignora los
campos de auditoría que no usa; no se creó un tipo aparte para no duplicar
la estructura.

**`Action` y `AttackVector` como tipos con método `Valid()`,** en lugar de
validar strings sueltos con un `switch` disperso por el código. El
enumerado y la regla de validez viven en el mismo lugar que el tipo.

**Un solo `entity_id` con prefijo (`ip:...`, `session:...`,
`network:...`) en lugar de dos campos separados** (tipo de entidad +
valor). Es más simple de transportar y de loguear, y alcanza para lo que
el evaluador necesita; si en algún momento hiciera falta filtrar por tipo
de entidad de forma más rica, se puede derivar del prefijo sin romper el
contrato.

**Regla de validación:** `Explanation` y al menos un `ContributingSignal`
son obligatorios cuando `Action` es `CHALLENGE` o `BLOCK` (para `ALLOW`
pueden quedar vacíos). `LLMExplanation` nunca es obligatorio — es
asíncrono y esa capacidad ni siquiera llegó a implementarse en el
proyecto.

**Documentado para uso futuro: la explicación del LLM nunca modificaría un
log de decisión ya emitido.** Los logs son de solo anexado (append-only).
Si el LLM llegara a implementarse y respondiera (potencialmente segundos
después), se emitiría un evento de auditoría separado (por ejemplo, del
tipo "decision_explanation"), correlacionado con la decisión original por
`RequestID` — o por un `DecisionID` dedicado, si más adelante resultara
que un request puede generar más de una decisión. Quien audite tendría que
cruzar ambos eventos, no esperar que el primero cambie.

**Pesos de `ContributingSignal`: se valida que sean finitos y no
negativos, no que sumen 1.** `Value` y `Weight` se rechazan si son `NaN` o
infinito; `Weight` además se rechaza si es negativo. No se exige que los
pesos de una decisión sumen exactamente 1 — esa normalización depende de
cómo funcione el algoritmo de combinación de señales de cada detector, que
en el momento de definir el contrato todavía no existía. Definirla sin el
algoritmo habría sido adivinar una regla que probablemente hubiera que
cambiar después.

**`ConfidenceScore` documentado como indicador de riesgo, no como
probabilidad calibrada.** Es un número de 0 a 1 que mide qué tan fuerte es
la evidencia de que la entidad esté llevando adelante el `attack_vector`
inferido — comparable entre decisiones, pero sin ninguna garantía
estadística de que "0.7" signifique "70% de probabilidad real". La acción
(`ALLOW`/`CHALLENGE`/`BLOCK`) sale de cortar ese score con dos umbrales
configurables, que viven en la configuración del motor (`Policy`, ver más
abajo), no en el contrato de `Decision`.

**Advertencia documentada sobre el barrido de umbrales:** re-evaluar
decisiones ya guardadas con umbrales distintos es útil como primera
aproximación, pero solo es exacto si las decisiones no afectan el estado
del propio motor — y en la práctica sí lo afectan (un atacante bloqueado
deja de generar los eventos siguientes que un atacante permitido sí
generaría). Para validar de verdad un cambio de política hace falta
reproducir el tráfico contra el motor con los nuevos umbrales, no solo
reetiquetar decisiones guardadas — principio que después guio todo el
diseño de `internal/tuning` (sección 10), que sí re-corre el motor
completo por cada candidato en vez de reetiquetar decisiones.

### `Policy`: los umbrales que traducen `RiskScore` en acción

**Decisión — `internal/engine/policy.go`:
`Policy{ChallengeThreshold, BlockThreshold}`**, validando
`0 ≤ ChallengeThreshold < BlockThreshold ≤ 1`. Los dos límites son
inclusivos (`score ≥ BlockThreshold → BLOCK`, comprobado primero; si no,
`score ≥ ChallengeThreshold → CHALLENGE`; si no, `ALLOW`). Los umbrales
viven acá, nunca en un detector individual.

**Semántica consistente para "disparó pero queda en `ALLOW`".** La
`Decision` siempre refleja la evidencia real observada (`AttackVector`,
`ConfidenceScore`, `EntityID`, señales); `Action` refleja qué se hizo con
esa evidencia. Son preguntas distintas. Si algún `Finding` disparó, aunque
el score no alcance `ChallengeThreshold`, la `Decision` conserva el
vector, el score real (no 0), el `EntityID` del principal y sus señales —
nunca se descartan solo porque la acción terminó en `ALLOW`. Solo cuando
ningún detector disparó cae al default "nada que reportar"
(`AttackVector=unknown`, score `0`, `EntityID="ip:"+client_ip`).

**`Decision.ContributingSignals` = solo las del finding principal.** Se
evaluó concatenar las señales de todos los detectores que dispararon, y se
descartó: los `Weight` de cada detector están normalizados dentro de su
propio modelo de score — mezclarlas haría parecer que son parte de un
único modelo ponderado, cuando son sistemas de puntaje independientes. Si
un segundo detector también disparó (con menor score), se lo menciona en
una frase corta dentro de `Explanation` — auditable, sin mezclar listas de
señales de proveniencia distinta.

**Empate exacto entre detectores: gana `credential_stuffing`, regla fija
y documentada.** La evidencia de credential stuffing distribuido exige
corroboración entre múltiples IPs independientes — una forma de evidencia
estructuralmente más difícil de disparar por casualidad que el patrón de
una sola entidad que mira `slow_scan`. Prioridad completa de desempate:
`credential_stuffing(0) > slow_scan(1) > statistical_anomaly(2)`.

**Regla de atribución (código, no threshold, agregada más adelante — ver
detalle y motivación completa en la sección 6).** Un detector específico
(`credential_stuffing`/`slow_scan`) `Triggered` siempre gana la atribución
de `AttackVector`/`EntityID`/`ContributingSignals` sobre
`statistical_anomaly`, sin importar el `RiskScore` relativo;
`Action`/`ConfidenceScore` siguen viniendo del mayor `RiskScore` entre
todos los `Triggered`, sin cambios.

### Calibración de `ChallengeThreshold`/`BlockThreshold`

**Contexto.** Con la detector layer ya congelada (credential_stuffing
`CSw2`, slow_scan `S3`, statistical_anomaly `A3` — secciones 4, 5 y 6), se
calibró Policy por separado, dejando `ScoreFloor` sin cambios en los tres
detectores — Policy está downstream de los detectores, y se quiso aislar
su efecto antes de alterar la escala de `RiskScore`.

**Optimización de arquitectura: reaplicar Policy sin re-correr
detectores.** Como el `RiskScore`/`AttackVector` de cada decisión no
depende de `ChallengeThreshold`/`BlockThreshold` (Policy solo decide la
Action a partir de un RiskScore ya calculado), se agregó
`engine.Policy.ActionFor` e `internal/tuning.ReapplyPolicy`/
`RunResultWithPolicy`: reaplican Policy sobre decisiones ya calculadas,
sin volver a construir ni correr ningún detector. Verificado con un test
de equivalencia explícito: reaplicar la misma Policy que produjo las
decisiones originales da resultados bit-a-bit idénticos a una corrida
completa. El sweep de 9 combinaciones corrió en menos de 1 segundo gracias
a esto.

**Sweep: 9 combinaciones, Challenge ∈ {0.50,0.55,0.60}, Block ∈
{0.70,0.75,0.80}.**

**Hallazgo estructural central: `FalseBlockRate` fue 0.0000 en los 9
candidatos, en los tres ratios, sin excepción, sobre tuning.** Con la
detector layer congelada y `ScoreFloor` actuales, el RiskScore de tráfico
legítimo nunca cruzaba ningún `BlockThreshold` del grid — consistente con
la distribución de RiskScore ya documentada (statistical_anomaly legit
p95≈0.46, muy por debajo de 0.70). Esto simplificó la lectura del sweep:
en el dataset de tuning, elegir `BlockThreshold` no tenía ningún costo
observado sobre usuarios legítimos — solo decidía qué tan agresivamente se
trataba al tráfico malicioso ya detectado (BLOCK vs CHALLENGE).

**Segundo hallazgo: las métricas Broad son idénticas entre los 3 valores
de `BlockThreshold`, para un mismo `ChallengeThreshold`.** Es matemático:
Broad cuenta CHALLENGE y BLOCK como la misma "predicción positiva", así
que mover la frontera entre CHALLENGE y BLOCK nunca cambia si un evento es
positivo en términos Broad — solo `BlockThreshold` afecta `StrictRecall`
(BLOCK puro) y la atribución de `AttackVectorRecall` strict.

| ChallengeThreshold | FPR@0% | Precision@10% | Recall@10% | F1@10% | Precision@30% | Recall@30% | F1@30% |
|---|---|---|---|---|---|---|---|
| 0.50 | 0.0381 | 0.7697 | 0.9203 | 0.8383 | 0.9460 | 0.7559 | 0.8403 |
| 0.55 | 0.0195 | 0.8380 | 0.7246 | 0.7772 | 0.9617 | 0.6208 | 0.7545 |
| 0.60 | 0.0086 | 0.8889 | 0.5604 | 0.6874 | 0.9751 | 0.5707 | 0.7200 |

Subir `ChallengeThreshold` reduce el FPR de forma monótona (bueno) pero
también reduce Recall/F1 de forma pronunciada (0.50→0.60 casi divide a la
mitad el recall a 10% y 30%). El Range (max-min entre seeds) de
BroadRecall a 30% baja de 0.316 (Challenge=0.50) a 0.266 (0.55) a 0.153
(0.60) — subir Challenge no solo baja el recall, también lo hace más
estable entre seeds, a costa de perder cobertura.

**Tres opciones propuestas, con trade-offs claramente distintos:**

| Opción | Config | Perfil |
|---|---|---|
| A — Cobertura primero | Challenge=0.50, Block=0.70 (o 0.75/0.80, Broad idéntico) | Mejor Recall/F1 (0.92/0.76, F1≈0.84), pero mayor FPR (0.033-0.038) y la mayor inestabilidad entre seeds (Range 0.32 @30%). |
| B — Balanceada | Challenge=0.55, Block=0.70-0.80 | FPR bastante más bajo (0.011-0.020), Precision alta (0.84-0.96), pero Recall/F1 caen sensiblemente (0.72/0.62, F1≈0.75-0.78). |
| C — Precisión/mínima fricción | Challenge=0.60, Block=0.70-0.80 | El FPR más bajo del grid (0.007-0.009), pero Recall se derrumba más (0.56/0.57, F1≈0.69-0.72). La más estable entre seeds. |

### Policy final aprobada: `ChallengeThreshold=0.50`, `BlockThreshold=0.75`

**Justificación.** Subir Challenge a 0.55/0.60 reduce FPR pero sacrifica
demasiado Broad recall; Block=0.80 es demasiado conservador respecto a los
RiskScores maliciosos observados; Block=0.70 es más agresivo y el dataset
legítimo de tuning no estresa suficientemente todos los patrones benignos
como para confiar en el margen; 0.75 es el punto intermedio.
`FalseBlockRate` fue 0 en las 9 combinaciones del grid de tuning, pero
**se documentó explícitamente que eso es una propiedad de esos datasets de
tuning, no una garantía general** — no se debía asumir que se mantendría
igual contra tráfico real o incluso contra holdout.

**Hallazgo sobre `credential_stuffing` y `StrictRecall`, corregido
después.** Se había dicho inicialmente que `CS Strict recall = 0.0000` en
los 9 candidatos del sweep sin matizar — una relectura posterior mostró
que eso solo era exacto a 10% (muestra chica, genuinamente 0 ahí); a 30%
`CS Strict recall` ya era sustancial (0.57-0.74) antes de este cambio
también. La explicación: la RiskScore mediana de `credential_stuffing`
sobre tráfico malicioso (~0.77) ya solía ser más alta que la de
`statistical_anomaly` (~0.50) en los eventos donde ambos coincidían, así
que `credential_stuffing` ya ganaba el desempate por score en la mayoría
de esos casos.

### Configuración final de Policy

| Parámetro | Valor |
|---|---|
| ChallengeThreshold | 0.50 |
| BlockThreshold | 0.75 |
| ScoreFloor (los tres detectores) | sin cambios, nunca tocado durante la calibración |

### Resultado en holdout: la garantía de `FalseBlockRate=0` no generalizó

**Hallazgo central, no visto en tuning: 3 falsos BLOCK reales en
holdout.** En tuning, `FalseBlockRate` fue exactamente 0.0000 en los 9
candidatos — documentado explícitamente como "propiedad de esos datasets
de tuning, no garantía general". En holdout, esa garantía se rompió: la
configuración final tuvo 3 eventos legítimos bloqueados de verdad a 0%
(seed 203), `FalseBlockRate=0.0008` (3 de 3628) — chico, pero real y
distinto de cero por primera vez en todo el proceso. La causa (el baseline
global de `statistical_anomaly` cruzando 0.7722 sobre tráfico legítimo en
holdout, contra un máximo de 0.6998-0.7079 en tuning) está descrita en
detalle en la sección 6.

**También se invirtió el signo de la comparación baseline-vs-final en
`FPR@0%`:** en tuning, la configuración final tenía FPR menor que el
baseline original (0.0381 vs. 0.0469); en holdout, la configuración final
tiene FPR mayor (0.0617 vs. 0.0529). Ambos FPR siguen siendo bajos en
términos absolutos, pero es una señal real de que la mejora de FPR@0%
observada en tuning no generalizó en la misma dirección.

**No se propuso ningún threshold nuevo a partir de estos resultados.**
Detector config, Policy y ScoreFloor permanecieron exactamente como se
habían congelado en el checkpoint pre-holdout, aunque el holdout mostrara
puntos peores que tuning (FPR@0%, StrictRecall@10%, CS RecallDetector@10%)
— siguiendo el mismo principio, ya documentado en el contrato de
`Decision`, de que un holdout corrido una sola vez y después usado para
re-ajustar deja de ser una medición honesta de generalización.

## 9. Observabilidad

### Objetivo y arquitectura

**Problema.** Cumplir el requisito de observabilidad del challenge con una
solución pequeña, local, reproducible y fácil de explicar: métricas reales
del motor (no decorativas), visibles en un dashboard de Grafana
provisionado automáticamente, sin exigirle Docker/Internet a ningún test
unitario.

**Decisión.**

```
cmd/engine (Go)  --OTLP/gRPC-->  OpenTelemetry Collector  --scrape-->  Prometheus  --query-->  Grafana
```

Se evaluó la alternativa más simple — el exportador Prometheus del propio
SDK de OTel, exponiendo `/metrics` directamente desde `cmd/engine`, sin
Collector — y se descartó: acoplaría el proceso Go al formato de
exposición de Prometheus específicamente, mientras que con OTLP el proceso
Go nunca sabe qué backend hay detrás (mañana se cambia Prometheus por otra
cosa tocando solo el Collector). El costo extra — un contenedor y un YAML
— es chico frente a lo que se gana.

**Qué corre en Docker Compose vs. en el proceso Go.** Los tres
contenedores (`otel-collector`, `prometheus`, `grafana`) corren en
`docker-compose.yml`. `cmd/engine` sigue corriendo local
(`go run ./cmd/engine`), apuntando su exportador OTLP a `localhost:4317` —
evita escribir un `Dockerfile` para el motor y mantiene el ciclo de
desarrollo simple.

**Versiones de imagen fijas, nunca `latest`** (verificadas contra el
registry antes de fijarlas): `otel/opentelemetry-collector-contrib:0.113.0`,
`prom/prometheus:v2.54.1`, `grafana/grafana:11.2.0`.

### Dónde vive el SDK de OTel, y quién nunca lo importa

**Un paquete nuevo, `internal/telemetry`, es el único del proyecto que
importa el SDK de OpenTelemetry para las métricas de dominio.**
`internal/telemetry.Init(ctx, cfg)` se llama una sola vez, al principio de
`cmd/engine/main()`; el `shutdown` que devuelve se llama una sola vez, al
final. Ni `internal/engine`, ni `internal/asn`, ni `internal/httpapi`
importan OpenTelemetry — cada uno define su propia interfaz mínima de
consumo (`engine.FindingsRecorder`, `asn.MetricsRecorder`,
`httpapi.DecisionRecorder`), que `internal/telemetry` implementa desde
afuera por tipado estructural — mismo criterio que ya usaba
`internal/asn.Resolver` para satisfacer `credstuffing.NetworkResolver`
(sección 7).

**Dónde se instrumenta sin contaminar el dominio.**
`internal/credstuffing`, `internal/slowscan` e `internal/anomaly`: cero
cambios, ningún import de OpenTelemetry. `internal/httpapi` agrega
`DecisionRecorder` (interfaz mínima, nil-safe con un no-op por defecto).
`internal/engine` agrega `FindingsRecorder` a `BehavioralDecider`, con la
misma convención. `internal/asn` agrega `MetricsRecorder` a `Resolver`.
Las tres son implementadas desde `internal/telemetry`, cableadas en
`cmd/engine/main.go`.

### Métricas — verificadas de verdad, no asumidas

**Decisión de proceso.** No asumir el nombre real que `otelhttp` exporta y
verificarlo durante la integración. Se corrió el stack completo, se
generó tráfico real, y se leyó directamente el endpoint de métricas del
exportador Prometheus del Collector. Nombres reales confirmados:

| Métrica (nombre real en Prometheus) | Tipo | Unidad | Labels | Dónde se registra | Pregunta que responde |
|---|---|---|---|---|---|
| `http_server_request_duration_seconds` | Histogram | s | `http_route` (2 valores), `http_request_method`, `http_response_status_code` | `otelhttp.NewHandler` envolviendo el mux en `cmd/engine/main.go` | Volumen y latencia end-to-end de cada endpoint |
| `waf_decisions_total` | Counter | 1 | `action` (3), `attack_vector` (3) | `httpapi.handleEvents`, justo después de `Decide` | Decisiones por action y por attack_vector |
| `waf_detector_findings_total` | Counter | 1 | `detector` (3) | `engine.BehavioralDecider.Decide`, por cada detector con `Finding.Triggered` | Qué detector dispara, incluso el que pierde el desempate |
| `waf_asn_cache_total` | Counter | 1 | `result` (hit/miss) | `asn.Resolver.Resolve`, según `cacheGet` | Efectividad del caché de ASN |
| `waf_asn_resolve_total` | Counter | 1 | `result` (success/failure/capacity_timeout) | `asn.Resolver.Resolve`, tras `fetch` o tras el timeout de capacidad | ¿RIPEstat responde? ¿Cuánto pesa la contención local? |
| `waf_asn_provider_duration_seconds` | Histogram | s | `result` (success/failure) | `asn.Resolver.Resolve`, alrededor de `fetch` | Cuánto tarda realmente la llamada HTTP al proveedor |
| `waf_anomaly_score_bucket` | Histogram | 1 | ninguno | `engine.BehavioralDecider.Decide`, en CADA evaluación de `statistical_anomaly` (dispare o no) | Distribución completa del `RiskScore` de anomaly, no solo la cola que dispara |

**Renombre aplicado a la métrica de duración de ASN.** Mide
específicamente la llamada HTTP a `fetch`, nunca `Resolve()` completo (que
también incluye la espera de capacidad y el caché) — por eso se llama
`waf.asn.provider.duration` (→ `waf_asn_provider_duration_seconds` en
Prometheus), no `waf.asn.resolve.duration`. Verificado en la demo:
`waf_asn_resolve_total{result="success"}=30` junto con
`waf_asn_provider_duration_seconds_count{result="success"}=30` —
exactamente una medición de duración por cada resolución real, nunca por
los `capacity_timeout`.

**`waf.detector.findings` usa el nombre del detector ya registrado
explícitamente**, nunca se infiere con un `type switch` sobre el detector
concreto.

**Decisión explícita de NO agregar** una métrica de latencia solo para
`engine.Decide`: `httpapi.handleEvents` hace
decode→validate→Decide→encode, y decode/validate/encode de un evento son
microsegundos frente al trabajo de los detectores — sería casi idéntica a
la latencia HTTP de `POST /v1/events` y solo agregaría una serie más sin
información nueva.

### Cobertura del requisito de observabilidad del challenge

**Problema.** El enunciado pide cubrir explícitamente, entre otras,
`requests_analyzed_total`, `decisions_by_action_total`, `fp_rate`,
`model_inference_duration`, `anomaly_score_histogram` y (si se usa LLM)
`llm_call_duration`. Auditar esto contra lo ya construido encontró un solo
gap real.

**Decisión, requisito por requisito.**

- `requests_analyzed_total` y `decisions_by_action_total`: cubiertos por
  `waf_decisions_total` (total = suma de todas las series; "por acción" =
  el label `action`, la forma idiomática de expresarlo en Prometheus/OTel,
  no un contador separado por valor).
- `fp_rate`: **nunca una métrica runtime**. Un falso positivo requiere
  ground truth, y el motor no tiene acceso a ground truth en ningún
  momento de su ejecución — esa separación está verificada con tests
  dedicados (ver § 2, Validación de eventos). Calcular un "FPR" en runtime
  sería, en el mejor caso, una proxy inventada (por ejemplo, tasa de
  CHALLENGE+BLOCK), nunca un FPR real. El FPR real se calcula en el
  pipeline de evaluación offline (`cmd/eval`, `internal/tuning`, el
  holdout) — es el que se cita como resultado final en el README.
- `anomaly_score_histogram`: era el único gap real — no existía ningún
  histograma en vivo del score de `statistical_anomaly`, solo la
  distribución offline (con ground truth) de los reportes de tuning/holdout.
  Cerrado con `waf.anomaly.score` (ver tabla arriba): se registra en CADA
  evaluación de `statistical_anomaly`, dispare o no (0 cuando no dispara,
  incluido igual — mismo criterio que ya usan los reportes offline, para
  que el histograma en vivo sea consistente con cómo se reportan las
  distribuciones ahí). Se agregó como un método específico
  (`RecordAnomalyScore`) en la interfaz `engine.FindingsRecorder`, no como
  una generalización a los otros dos detectores — no la pedía el requisito,
  y hacerlo hubiera sido instrumentar algo que nadie iba a consumir.
- `model_inference_duration`: **no aplica**. `internal/anomaly` es un
  detector estadístico (Welford + z-scores), no un modelo ML entrenado —
  no hay ninguna fase de "inferencia" que medir.
- `llm_call_duration`: **no aplica**. El proyecto nunca implementó LLM en
  runtime (`decision.LLMExplanation` existe como campo del contrato, sin
  implementación).

**Trade-off.** `waf.anomaly.score` no lleva ningún atributo — ni siquiera
`detector`, porque ya es específico de uno solo — para no repetir la
discusión de cardinalidad de la sección siguiente por una métrica que de
por sí es de una sola serie.

### Cardinalidad

**Decisión.** Ningún label es `client_ip`, `request_id`, `entity_id`,
`session_id`, `login_user_hash`, ruta cruda ni un número de ASN
individual. Todos los labels son conjuntos fijos y chicos: `action` (3),
`attack_vector` (3), `detector` (3), `result` (2 o 3), `http_route` (2).
Combinación máxima observada: `waf_decisions_total` con 3×3=9 series.

### Fail-open: el diseño central de este componente

**Problema.** El motor de decisión no puede depender de que el Collector
de observabilidad esté disponible — un fallo de observabilidad nunca debe
frenar el servicio de seguridad.

**Decisión.** `internal/telemetry.Init` nunca devuelve un estado que le
impida a `cmd/engine` arrancar. Tres casos, cada uno probado:

1. `--otel-endpoint` vacío (default) → no-op sin ningún intento de red.
2. `--otel-endpoint` configurado pero el Collector no responde dentro de
   `--otel-connect-timeout` → no-op, `usedNoop=true`, tiempo total acotado
   cerca del timeout — nunca un error que frene el arranque (probado
   contra un puerto TCP real cerrado, sin mocks).
3. Collector alcanzable → `MeterProvider` real.

La verificación de "alcanzable o no" es síncrona y ocurre en `dial()`: se
arma un `*grpc.ClientConn` con `grpc.NewClient` (la forma moderna, que
nunca conecta por sí sola) y se espera explícitamente `connectivity.Ready`
con `conn.WaitForStateChange`, acotado por `ConnectTimeout` — se evitó la
vieja `grpc.WithBlock()` porque su propia documentación dice que
`NewClient` ya no la soporta.

`cmd/engine/main.go` logea la advertencia de fallback (`usedNoop &&
endpoint != ""`) — `internal/telemetry` nunca escribe logs por su cuenta,
para quedar testeable sin capturar stdout.

**`--otel-insecure` (default true).** La conexión gRPC local de este
proyecto usa `insecure.NewCredentials()` explícitamente vía
`--otel-insecure=true`. Documentado sin ambigüedad: esto es válido
únicamente para un Collector local en la misma máquina/red de confianza —
un endpoint remoto de producción debería correr con
`--otel-insecure=false`, que activa `credentials.NewTLS` con la
configuración estándar de verificación contra las CA del sistema.

**`otelhttp` con el `MeterProvider` explícito.** `cmd/engine/main.go` pasa
`otelhttp.WithMeterProvider(recorders.Provider)` en vez de depender del
proveedor global — se confirmó en la versión usada (`otelhttp` v0.71.0)
que la opción existe exactamente para esto, así que no hubo ninguna razón
técnica para no pasarlo explícito. Es la única excepción documentada, a
preferir la convención propia del proyecto (inyección explícita) sobre la
convención estándar de OTel (proveedor global): las métricas de dominio
sí siguen la inyección explícita de siempre.

**Apagado ordenado.** `cmd/engine/main.go` usa
`signal.NotifyContext(context.Background(), os.Interrupt,
syscall.SIGTERM)`. Al recibir la señal: `httpServer.Shutdown` con un
contexto acotado a 5s (deja de aceptar conexiones nuevas, drena las en
curso), y — recién después de que `ListenAndServe` retorna — un segundo
contexto nuevo y acotado a 5s, exclusivamente para el `Shutdown` de
telemetry (que hace flush del `MeterProvider` y cierra la conexión gRPC).
Nunca se reutiliza el `ctx` de la señal, que para ese momento ya está
cancelado y no daría ningún margen real al flush final. Verificado
manualmente (comportamiento de `main`, no de un paquete testeable): se
envió `SIGTERM` a un binario real corriendo con `--otel-endpoint`
configurado, y el log mostró una terminación limpia, sin quedar colgado.

### Tests sin Docker/Prometheus/Grafana/Internet

**Decisión.** Las interfaces mínimas se prueban con fakes en memoria
(`fakeFindingsRecorder`, `fakeMetricsRecorder`, `fakeDecisionRecorder`) —
mismo estilo que el `fakeResolver` de credential stuffing. El adaptador
real de `internal/telemetry` se prueba con `sdkmetric.NewManualReader()`
(sin ningún exportador de red): se registra una medición y se lee
sincrónicamente el resultado ya agregado, la forma oficialmente soportada
por el SDK de OTel para testear instrumentación sin Collector. Los tests
verifican, contra el `ManualReader`, el nombre exacto de cada instrumento
y sus atributos — el mismo nombre que después se confirmó en la demo
real.

### Docker Compose y provisioning de Grafana

`otel/collector-config.yaml` (receiver `otlp` gRPC, processor `batch`,
exporter `prometheus` en `:8889`); `prometheus/prometheus.yml` (un único
scrape job hacia `otel-collector:8889`);
`grafana/provisioning/datasources/datasource.yml` (datasource Prometheus
con `uid: prometheus` fijo, para que el JSON del dashboard pueda
referenciarlo sin variables de plantilla);
`grafana/provisioning/dashboards/dashboard-provider.yml` +
`grafana/dashboards/waf-engine.json` (8 paneles). Acceso anónimo de solo
lectura habilitado en Grafana (`GF_AUTH_ANONYMOUS_ENABLED=true`, rol
Viewer) — únicamente para que esta demo local no le exija login al
evaluador; el panel de administración sigue pidiendo `admin/admin`. Nunca
se expondría así fuera de una demo local.

### Verificación manual real, de punta a punta

Se corrió `docker compose up -d`, se levantó `cmd/engine` local apuntando
a `localhost:4317`, y se generó tráfico real de varias formas: ALLOW (5
requests normales); slow_scan (50 requests a rutas distintas, todas 404,
sobre una misma IP → `action=BLOCK`, `waf_detector_findings_total{detector="slow_scan"}=36`);
statistical_anomaly (un baseline de 200 IPs de un solo request cada una
seguido de una entidad nueva sosteniendo `Referer` ausente en 10 requests
→ `Finding.Triggered=true` con `without_referer_ratio_z≈9.87`, risk score
0.33, por debajo del challenge threshold de ese momento así que `action`
siguió en `ALLOW` pero con la evidencia completa preservada); credential
stuffing con RIPEstat real (30 IPs públicas de Google, 15 cuentas, 80% de
fallos → `waf_asn_cache_total{result="hit"}=30` y `{result="miss"}=30`,
cada IP se resuelve dos veces por evento — una vez desde `Observe`, otra
desde `Evaluate`; la primera siempre miss, la segunda siempre hit gracias
al caché, ningún comportamiento nuevo, solo confirma cómo ya funcionaba el
detector). Los ocho paneles se confirmaron cargados vía la propia API de
Grafana, y una query real ejecutada a través del proxy de Grafana hacia
Prometheus devolvió datos reales — no solo "la config parece bien", sino
"Grafana efectivamente sirve estos números".

El hallazgo instructivo sobre la dificultad real de forzar
`statistical_anomaly` durante esta verificación (varianza cero
desactivando el z-score, y auto-contaminación del baseline entre intentos
fallidos consecutivos) está documentado en detalle en la sección 6.

### Criterios de cierre

`gofmt -l .` limpio; `go vet ./...` sin hallazgos; `go test -race ./...`
verde en todos los paquetes, incluido `internal/telemetry`; `docker
compose config` válido; el stack arranca localmente (3 contenedores
healthy); métricas reales (no inventadas) visibles en Prometheus y en
Grafana; dashboard funcional con 8 paneles, cargado sin ningún paso manual
del evaluador.

### Adenda — vulnerabilidad de dependencias detectada post-implementación

**Problema.** Un análisis de dependencias marcó
`google.golang.org/grpc@v1.83.1` con una vulnerabilidad HIGH.

**Investigación con dos fuentes independientes antes de tocar nada.**

1. `govulncheck` (el escáner oficial de Go, que hace análisis de
   alcanzabilidad real contra el código propio) no reportó ningún problema
   en `grpc` en absoluto, ni siquiera como "no alcanzable". En cambio
   encontró 31 vulnerabilidades reales de la librería estándar de Go,
   todas ya arregladas en parches posteriores a `go1.25.0` — consecuencia
   directa de que fijar las versiones del SDK de OTel había subido el `go`
   directive del módulo a exactamente `1.25.0` (ver sección 1).
2. Consulta directa a la API de OSV.dev por la versión exacta `1.83.1`:
   `GHSA-2v4p-qf9q-27wj` / `CVE-2026-84445` / `GO-2026-6443` — un panic de
   denegación de servicio en servidores gRPC configurados con
   `xds.NewGRPCServer()` (xDS), cuando un request llega sin los headers
   `:authority` ni `Host`. Este proyecto nunca usa gRPC como servidor XDS
   — `internal/telemetry` solo lo usa como cliente (`grpc.NewClient` para
   hablar con el Collector vía `otlpmetricgrpc`) — exactamente por eso
   `govulncheck` no lo marcó: el código vulnerable jamás es alcanzable
   desde este binario.

**Decisión.** Corrección aplicada de todas formas, aunque el código no
fuera alcanzable (es un bump de parche, sin riesgo, y elimina el ruido de
la alerta): `google.golang.org/grpc` a `v1.83.2` (la versión donde se
arregló la vulnerabilidad), y el `go` directive del módulo de `1.25.0` a
`1.25.14` (el último parche de la misma línea 1.25 — no un salto de
versión de lenguaje, solo la corrección de seguridad de la librería
estándar). Verificado: `govulncheck ./...` pasó de 31+ hallazgos a "No
vulnerabilities found", y el resto de la suite siguió en verde.

## 10. Evaluación y calibración

### El ground truth y su contrato: `LabeledEvent`

**Decisión — `LabeledEvent` vive en `internal/groundtruth`, no en
`internal/event`.** Es la única estructura del proyecto que junta un
`event.Event` con su `Label`. `LabeledEvent.Payload()` (nombre elegido a
propósito, no `ToEvent()`) devuelve únicamente la parte `Event` — es lo
único que el generador de tráfico debe enviarle al motor. El detalle
completo de las garantías de aislamiento que protegen este contrato está
en la sección 2.

### `internal/datagen`: generar tráfico legítimo con ground truth

**Reloj: se reutiliza `event.ManualClock`, sin tipo nuevo.** Cada sesión
legítima crea internamente su propio `ManualClock`, arrancado en el
momento que le pasa quien la llama, y lo va avanzando con saltos
aleatorios — no hace falta esperar tiempo real para simular una sesión de
varios minutos.

**Coherencia de tiempo al mezclar sesiones: cada sesión se genera con su
propio reloj interno; el orden global es responsabilidad de quien mezcla,
no de un reloj compartido.** Compartir un único reloj entre sesiones
concurrentes habría complicado el código sin necesidad. El generador que
mezcla varias sesiones (una por empleado de oficina) genera cada una por
separado y ordena el resultado por `Timestamp` antes de devolverlo — el
mismo principio se aplicó después al mezclar sesiones de distintos
perfiles y ataques en un único dataset: generar cada sesión con su propio
horario de inicio y ordenar el conjunto al final, nunca compartir un reloj
entre generadores.

**Aleatoriedad: wrapper `RNG` sobre `math/rand/v2`, con semilla.**
Reutilizado tanto por los perfiles legítimos como por los generadores de
ataque. La reproducibilidad se verificó comparando el JSON serializado de
dos corridas con la misma semilla — no alcanza con "revisar a ojo" que los
números se repiten, hay que probarlo contra la forma final en la que se va
a guardar el dataset.

**IPs y ASN simulados: los tres bloques reservados para documentación
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), con ASN
simulados en el rango 64512–65534 (privado, RFC 6996).** Antes de
implementar se verificó empíricamente (no de memoria) que estos rangos no
activan ninguna de las reglas de "IP privada" del `Validator` del contrato
de eventos — por lo tanto no hizo falta modificar el `Validator`. Los ASN
asignados a cada pool (`hosting-sim`, `residential-sim-a`,
`residential-sim-b`) son inventados por este generador; en ningún lugar
del código ni de la documentación se afirma que pertenezcan a un proveedor
real. El enriquecimiento real de IP (sección 7) se integró como un
adaptador independiente, que no tiene por qué conocer esta simulación —
y, de hecho, nunca puede resolver estos rangos (ver sección 7).

**`DefaultLoginPath` compartido.** Se extrajo como constante reutilizada
tanto por los perfiles legítimos como por el generador de campañas de
credential stuffing, así el ataque apunta al mismo endpoint que navegan
los usuarios legítimos, no a una aplicación simulada distinta. El perfil
de cliente API mantiene su propio endpoint de login — a propósito, es un
endpoint distinto de la misma aplicación.

**Tres perfiles legítimos, como datos de un mismo `struct`, no como
código separado por perfil:**

| Perfil | Trampa que cubre |
|---|---|
| Navegante | Caso normal, pero con `BrokenLinkProbability` (algún 404 legítimo) y `LoginRetryProbability` (typo y reintento con la misma cuenta) — la diferencia clave con el credential stuffing, donde cada intento prueba una cuenta distinta |
| Cliente API / app móvil | Nunca manda referer ni pide assets estáticos — exactamente lo que buscaría el detector de escaneo lento, pero es tráfico legítimo |
| Oficina (NAT) | Varios empleados, cada uno con su propia sesión, comparten una única IP — trampa para cualquier regla que asuma "mucho volumen por IP = ataque" |

Un único `LegitProfile` con campos (pools de IP, si manda referer, si pide
assets, probabilidades) evita triplicar la misma lógica de generación —
los tres perfiles son instancias del mismo tipo con valores distintos. Un
cuarto perfil, `ProfileHostedTenant`, se construye a partir de
`ProfileAPIClient` cambiándole el nombre y el pool de IP a uno de hosting
compartido con los atacantes — así, si se ajusta algún parámetro de
`ProfileAPIClient`, el tenant hereda el cambio automáticamente.

**Validar eventos generados contra `event.Validator`: el reloj de
tolerancia se fija al timestamp del propio evento, no a un "ahora"
externo.** Los eventos generados pueden abarcar minutos u horas
simuladas, mientras que las tolerancias del `Validator` modelan la
ingesta en tiempo real, no la reproducción de un dataset ya generado. Por
eso, en los tests del generador, cada evento se valida con un `Validator`
cuyo reloj está fijado exactamente en el `timestamp` de ese mismo evento —
así se comprueba la forma correcta (IP pública, método válido, `path` con
`/`, status en rango, hash de login bien formado) sin que la regla de
tolerancia de tiempo, pensada para otro escenario, dé un falso rechazo.

### Diseño adversarial: que el tráfico sintético no sea artificialmente fácil de distinguir

**Problema.** Un dataset de ataque demasiado "limpio" haría que cualquier
detector simplista pareciera funcionar bien, sin medir nada realista.

**Ocho decisiones deliberadas, documentadas porque son las que se
defienden en una entrevista:**

1. Tasa por IP con tope duro de 3 intentos en credential stuffing —
   ningún rate-limit por IP puede verlo nunca, por construcción.
2. Sin ráfagas: los intentos se distribuyen en instantes aleatorios de
   toda la ventana, no juntos.
3. Ruido controlado a propósito (5% de reutilización de cuenta en
   credential stuffing, 1% de éxito, 30% de 403 entre los fallos) — un
   patrón perfectamente limpio sería, en sí mismo, una señal artificial.
4. User-Agent mixto (navegador normal y herramientas de script) en ambos
   ataques — ningún UA único alcanza para distinguir todo.
5. El escaneo lento mezcla rutas nunca vistas (85%) con rutas reales de
   la aplicación (15%) — un escáner 100% desconocido sería trivialmente
   distinguible con una sola regla de catálogo.
6. **La ausencia de `Referer` está compartida a propósito entre el
   perfil de cliente API (legítimo) y el escaneo lento (ataque).** No es
   un descuido: es una comprobación incorporada al propio dataset de que
   ningún detector futuro puede aprobar el challenge usando "falta de
   referer" como única señal — si lo hiciera, generaría falsos positivos
   contra el cliente API legítimo, y eso se mide en la evaluación.
7. Timing con jitter aleatorio en los dos ataques, nunca intervalos
   constantes.
8. IPs sorteadas de forma uniforme dentro de todo el /24 (Fisher-Yates),
   no en un rango secuencial artificial.

**Notas anotadas para trabajo futuro, ya resueltas en gran parte por el
diseño:**

- "No depender exclusivamente del ASN para identificar stuffing": ya
  cierto por diseño — el generador no calcula ni expone ninguna lógica de
  correlación por ASN, eso es responsabilidad del detector (sección 4),
  que combina la correlación por ASN con el ratio de fallos y la
  diversidad de cuentas, nunca el ASN solo.
- "Tráfico legítimo que comparta ASN con algunos atacantes": resuelto con
  `ProfileHostedTenant` (ver arriba) — así "esta IP es del ASN de
  hosting" deja de ser, por sí sola, una señal utilizable.
- "Los 404 legítimos no deben producir bloqueos injustificados": cubierto
  estructuralmente por `BrokenLinkProbability` en los perfiles Navegante y
  Oficina, que genera una tasa de 404 legítima mayor a cero — medido
  directamente por el escenario de 0% de tráfico malicioso en cada
  evaluación.
- "UA, ruta o ausencia de Referer no deben alcanzar por sí solos":
  incorporado en el diseño (puntos 4 y 6 de la lista de arriba), y medido
  cuantitativamente con la matriz de confusión en cada evaluación.

### Mezclador de escenarios: 0%, 10% y 30%

**Cómo se calcula el volumen malicioso, sin forzar el porcentaje exacto.**
Primero se genera toda la población legítima (incluidos los tenants sobre
el ASN de hosting) y se cuenta cuántos eventos produjo de verdad (`L`) —
no se adivina de antemano, porque cada sesión genera un número de eventos
que depende del azar. Con `L` conocido, se calcula el volumen malicioso
objetivo (`M = L · ratio / (1 - ratio)`) y se reparte entre los dos
ataques: el credential stuffing recibe como máximo el 30% de ese volumen,
reflejando que es, por diseño, un ataque de bajo volumen — no se infla
artificialmente para "completar" el porcentaje. El escaneo lento absorbe
el resto. No se recorta ningún evento a mitad de una sesión para ajustar
el número exacto — eso rompería la coherencia narrativa de una sesión. En
cambio, se calcula el porcentaje real alcanzado (exacto, porque el ground
truth se conoce) y se guarda en `manifest.json`. Con la población por
defecto y semilla 42: 8.85% real para el objetivo de 10%, y 28.51% real
para el objetivo de 30% — ambos dentro de la tolerancia de ±3 puntos
porcentuales fijada como criterio.

**Simplificación consciente: los dos volúmenes de ataque se estiman en
paralelo, no en dos pasadas.** Se había planteado generar primero el
stuffing, medir su volumen real, y recién ahí calcular cuánto escaneo hace
falta para completar el resto. Se simplificó: los dos volúmenes se
estiman a la vez, a partir de promedios esperados — más simple de razonar,
con diferencia práctica chica porque ambos promedios son razonablemente
estables con las cantidades usadas.

**Direcciones disjuntas entre tenants legítimos y atacantes, mediante un
sorteo coordinado — no por probabilidad baja de choque.** Antes de generar
los ataques, se sortean primero las IPs de los tenants legítimos, y recién
después las IPs atacantes se sortean con un método que nunca devuelve una
dirección ya usada por los tenants. Se evaluó la alternativa de sortear
ambos conjuntos por separado y aceptar una probabilidad chica de
superposición, pero con las cantidades usadas (8 tenants, hasta 150 IPs de
stuffing, sobre un pool de 254) el número esperado de choques no era
despreciable — se prefirió la garantía exacta.

**No se asume que una IP tiene una única etiqueta — la evaluación siempre
se hace por `request_id`.** La garantía de direcciones disjuntas de este
escenario es una simplificación deliberada para tener un primer dataset
limpio de evaluar, no una regla general del proyecto. Queda anotado como
extensión natural: generar a propósito un escenario donde una misma IP
mezcle tráfico legítimo y malicioso, y confirmar que el mecanismo de
evaluación —que ya cruza por `request_id`, nunca por entidad— sigue
funcionando igual de bien ahí.

**Formato de archivos: dos JSONL más un manifiesto, por escenario.**
`events.jsonl` (exactamente `LabeledEvent.Payload()`, sin ninguna etiqueta
— es lo único a lo que tiene acceso el código que arma el request hacia el
motor), `labels.jsonl` (`request_id` + `label`, el ground truth) y
`manifest.json` (semilla, configuración y estadísticas, sin ninguna marca
de tiempo real de generación, para que el manifiesto también sea
reproducible byte a byte). Verificado por test que `events.jsonl` y
`labels.jsonl` tienen exactamente el mismo conjunto de `request_id` — ni
de más, ni de menos.

**`cmd/datagen`**, con `--seed`, `--ratio` (0, 10 o 30) y `--out`. Los
objetivos `make data-0`, `make data-10`, `make data-30` y `make data-all`
lo invocan con la semilla 42 por defecto.

**Ventana del escenario: 6 horas simuladas**, elegida para contener
cómodamente la ventana de 3 horas del stuffing (con margen antes y
después) y las sesiones de escaneo lento (hasta 3 horas cada una) —
verificado por test que ningún evento de ataque cae fuera de la ventana
del escenario.

### `internal/eval`: el evaluador

**Alcance.** `Evaluate` recibe `[]decision.Decision` en memoria. Junto con
`internal/datagen`, es el único paquete del proyecto que importa
`internal/groundtruth` — ver la explicación de por qué esto no contradice
la regla de aislamiento en la sección 1.

**Cada métrica revisa su propio denominador, de forma independiente — no
hay una regla del tipo "en el escenario de 0% todo es N/A".**
`Precision` depende de cuántas veces el motor predijo positivo (`TP+FP`);
`Recall` y `FNR` dependen de cuántos positivos reales había (`TP+FN`);
`FPR` depende de cuántos negativos reales había (`FP+TN`). Son tres
condiciones distintas. En el escenario de 0% de tráfico malicioso, `TP+FN`
siempre es 0 (no hay ningún ataque real), así que `Recall` y `FNR` son
N/A — pero si el motor bloqueó aunque sea un evento legítimo por error,
`TP+FP > 0` y `Precision` sí está definida (va a dar 0%, porque ese
positivo predicho fue un falso positivo).

**Ninguna métrica indefinida se disimula con un 0 o un 1.** El tipo
`Ratio` (`{Value float64; Defined bool}`) obliga a que quien lea el
resultado compruebe explícitamente si el número tiene sentido, en vez de
asumirlo.

**Dos políticas de evaluación, siempre las dos, nunca una a elección.**
Estricta (solo `BLOCK` es positivo) y amplia (`CHALLENGE` o `BLOCK`) —
porque un `CHALLENGE` es una molestia mucho más barata que un `BLOCK`, y
evaluar solo con la política estricta penalizaría injustamente a un motor
que contiene el ataque con fricción baja en vez de bloquear directamente.

**Recall separado por `credential_stuffing` y `slow_scan`, pero Precision
y FPR siguen siendo globales.** Un falso positivo (molestar a un usuario
legítimo) no "pertenece" a ningún tipo de ataque en particular, así que
desglosarlo por tipo no tendría sentido — solo el recall (¿de los ataques
de este tipo, cuántos atrapé?) se desglosa.

**Atribución del vector de ataque: tres categorías, no dos, y solo sobre
los verdaderos positivos.** Correcto / Desconocido / Incorrecto — nunca se
mezcla "desconocido" con "incorrecto": un motor que dice honestamente
`unknown` cuando no está seguro no debería penalizarse igual que uno que
afirma un vector concreto y se equivoca. La precisión de atribución
(`Correct / (Correct + Incorrect)`) deja `Unknown` fuera del denominador —
y si un motor siempre responde `unknown`, esa precisión es N/A, no 0%.
Esto solo se evalúa entre los verdaderos positivos de la política amplia.

**F1**, agregado más adelante a `internal/eval.Metrics` — indefinido (N/A)
si Precision o Recall lo son, o si ambas dan exactamente 0.

**Integridad de datos: cuatro problemas detectados, ninguno frena el
cálculo, pero todos quedan marcados.** `request_id` duplicado en las
etiquetas, `request_id` duplicado entre las decisiones, etiqueta
desconocida, decisión faltante y decisión sobrante. Las decisiones
faltantes o sobrantes se excluyen del cálculo de la matriz de confusión
(no se puede contar una acción que no existe, y tratar una decisión
faltante como un `ALLOW` implícito escondería posibles bugs del motor).
`Issues.Clean()` es la señal explícita de que un resultado es un
diagnóstico parcial, no definitivo — cualquier código que lea un
`Result` tiene que comprobar `Clean()` antes de darlo por bueno.

**Evaluación por entidad o por campaña: documentada como trabajo futuro,
no implementada.** Se mide únicamente por `request_id`. Una campaña de
credential stuffing distribuido puede involucrar cientos de IPs, y una IP
compartida no necesariamente tiene una única etiqueta — por eso la
evaluación por entidad, si se construyera en el futuro, tendría que seguir
agregando sobre etiquetas por `request_id`, nunca asumir que "esta IP =
este resultado".

**Motores ficticios, solo dentro de los tests.** `decideAllowAll`,
`decideBlockAll` y `decidePerfectOracle` confirman que el propio evaluador
es confiable antes de usarlo contra un motor real: "permitir todo" da
recall 0%, "bloquear todo" da FPR 100%, y el "oráculo perfecto" (que hace
trampa mirando la etiqueta) da 100% en todo.

### `cmd/eval`: la puerta de entrada por archivo

**Carga de decisiones: tres categorías de problema, no dos.**
`LoadDecisions` separa cada línea de `decisions.jsonl` en: decisión
utilizable, `InvalidIDs` (JSON válido y `request_id` identificable, pero
la decisión no pasa `decision.Validate()`) y `CorruptLines` (la línea no
se pudo interpretar en absoluto — reportada por número de línea, no hay
ningún ID confiable). Ninguna de las dos categorías de problema entra al
cálculo de métricas, y ninguna se convierte silenciosamente en un `ALLOW`
implícito.

**Evitar reportar el mismo problema dos veces.** Si la única decisión de
un `request_id` es inválida, sin ajuste extra ese `request_id` terminaría
apareciendo tanto en `InvalidDecisionIDs` como en `MissingDecisionIDs`.
`EvaluateDecisions` corrige esto quitando de `MissingDecisionIDs`
cualquier `request_id` que ya esté en `InvalidDecisionIDs`.

**Reporte Markdown: nunca disimula un N/A, nunca esconde una
advertencia.** `RenderMarkdown` reutiliza `Ratio.Defined` para imprimir
literalmente `N/A` en vez de un `0.000` cuando un denominador es cero. Si
`Issues.Clean()` es `false`, el reporte abre con un bloque de advertencia,
con la lista completa de problemas, antes de mostrar cualquier matriz o
métrica.

**Tres códigos de salida, no dos.** `0` (limpio); `1` (el reporte se
generó, pero `Issues.Clean()` es `false` — no es un error operativo, es
información sobre la calidad del dato de entrada); `2` (el comando no pudo
completar su trabajo — archivo inexistente, fallo de lectura o
escritura). Separar estos dos últimos casos importa porque un script (o
una persona, a mano) necesita poder distinguir "esto no corrió" de "esto
corrió pero avisa que el dato está incompleto" sin parsear el texto del
reporte.

### `internal/baseline`: la línea base de rate limiting por IP

**Problema.** Hacía falta un punto de comparación conocido, medido sobre
los mismos escenarios y con el mismo `cmd/eval`, contra el que comparar el
motor conductual — la técnica de mitigación más simple y más común contra
tráfico abusivo.

**Decisión.** `internal/baseline` es un rate limiter tradicional por IP,
con ventana deslizante. El nombre del paquete (`baseline`, no `engine` ni
nada parecido) es deliberado, para que nunca se confunda con el detector
real del challenge. Nunca importa `internal/groundtruth` — decide
únicamente con lo que ve en `event.Event`, la misma separación que exige
el resto del motor.

**Dos modos de conteo, sin duplicar la identificación de rutas de
login.** `Config.Mode` puede ser `"all"` (cuenta toda petición de la IP) o
`"auth"` (cuenta únicamente las peticiones que `event.AuthPathMatcher`
reconoce como ruta de autenticación, reutilizado tal cual).

**Ventana deslizante, no de bloques fijos.** Se eligió deslizante en vez
de fija ("se resetea cada minuto en punto") porque una ventana fija tiene
un hueco conocido: un atacante puede mandar el límite completo justo antes
de que cierre una ventana y el límite completo otra vez apenas abre la
siguiente, duplicando el volumen real en segundos sin que ningún contador
lo vea. La implementación usa una cola por IP que se recorta por adelante
(lo que ya salió de la ventana) y crece por atrás (el evento actual) —
costo amortizado bajo por evento, válido porque `datagen` genera
`events.jsonl` ya ordenado (a diferencia de `internal/profile`, sección 3,
que sí necesitó resolver el caso de eventos fuera de orden).

**Acciones: solo ALLOW y BLOCK, vector siempre `unknown`.** Sin
`CHALLENGE` — un rate limiter tradicional de referencia tiene un único
umbral binario. El `AttackVector` de toda decisión `BLOCK` es `unknown`:
un conteo de peticiones por IP no tiene ninguna forma de distinguir
credential stuffing de escaneo — ambos "se ven" igual (muchas peticiones).
Esta limitación de atribución es intencional y es justamente parte de la
comparación contra el motor conductual.

**`ConfidenceScore`: revisado, ya no satura de entrada.** La primera
versión proponía `min(count/MaxRequests, 1.0)`, que con el doble del
límite ya da `1.0` y no distingue más entre el doble y las cien veces el
límite. La fórmula final es `1 - MaxRequests/count` (solo para `BLOCK`):
count=MaxRequests+1 → score≈0; count=2×MaxRequests → score=0.5;
count=10×MaxRequests → score=0.9; count→∞ → score→1 (nunca lo toca). Sigue
siendo una heurística legible, no una probabilidad calibrada.

**Calibración: semilla distinta a la del reporte, y una predicción escrita
antes de correr el número.** Se generaron datasets de calibración con
`--seed 1`, separados de los datasets de reporte (`--seed 42`). El umbral
se eligió mirando solo los datos de calibración, y recién después se
corrió, ya fijo, contra los datos de reporte.

**Predicción explícita, confirmada con datos.** Antes de correr nada: esta
línea base tenía que verse mal contra el credential stuffing distribuido
de baja intensidad (150 IPs con 1-3 intentos cada una) — por diseño,
ningún umbral razonable de "peticiones por IP en una ventana corta" podía
cruzarse con esos números. Barrido sobre los datos de calibración,
política estricta, `MaxRequests` ∈ {2,3,5,10,20,50,100,200} y `Window` ∈
{60s,300s,600s}, en los dos modos: en modo `all`, umbrales laxos nunca
bloqueaban nada, umbrales ajustados generaban falsos positivos (FPR 6%-80%)
sin que el recall subiera nunca de 0%; en modo `auth`, FPR = 0.000 en
todos los umbrales probados, pero Recall = 0.000 también en todos —
credential stuffing nunca mandaba más de 3 intentos de login por IP en 3
horas, muy por debajo de cualquier umbral probado incluso en la ventana
más ancha.

**Configuración final elegida: `mode=auth, max-requests=5, window=300s`**
— un valor de referencia habitual para rate limiting de login en la
práctica (similar al recomendado por OWASP), y la única combinación que en
la calibración nunca generó un falso positivo. Resultado real medido sobre
`scenario-10`, política estricta: `TP=0 FP=0 FN=121 TN=1246 —
Precision=N/A Recall=0.000 FPR=0.000 Accuracy=0.911`
(`credential_stuffing`: Recall=0.000; `slow_scan`: Recall=0.000). 0 BLOCK
en los tres escenarios de reporte. Esto no fue un error del baseline ni de
la evaluación: fue exactamente la predicción escrita antes de medir —
confirma con datos reales, no solo en teoría, por qué un rate limit
tradicional por IP, incluso bien calibrado y sin ningún falso positivo, no
alcanza contra un ataque distribuido de baja intensidad, y es la
justificación medida de por qué hace falta el motor conductual.

**Limitación documentada, no resuelta: NAT.** Varias sesiones legítimas
distintas detrás de la misma IP comparten el mismo contador y pueden
terminar bloqueadas entre sí aunque cada una sea individualmente legítima.
Con `mode=auth` esto es improbable en la práctica (pocos intentos de login
por sesión), pero sigue siendo una limitación estructural de cualquier
rate limit puramente por IP.

### Infraestructura de tuning: medir sin overfitting

**Objetivo.** Medir y calibrar el motor conductual de forma reproducible,
separando calidad del detector (`Finding` → `Triggered`, risk scoring) de
calidad de la política (`ALLOW`/`CHALLENGE`/`BLOCK`), usando datasets de
tuning (semillas 101/102/103) y de holdout final (semillas 201/202/203)
generados con semillas distintas.

**`internal/tuning.BaselineCandidate()` como única fuente de verdad del
punto de partida.** Se movieron (no copiaron) las funciones de
configuración por defecto de cada detector desde `cmd/engine/main.go` a
`internal/engine/defaults.go`, para que el "baseline" de la evaluación
fuera exactamente la configuración que servía `cmd/engine`, nunca una
copia a mano que pudiera desincronizarse.

**`internal/datagen.SimulatedASNResolver`** — resolver determinista
offline (IP → ASN simulado, por prefijo `/24`, usando los mismos pools con
los que se generó el tráfico) para credential stuffing en el tuning.
Nunca usa RIPEstat contra IPs sintéticas — no tendría sentido, y ya se
documentó (sección 7) que RFC 5737 nunca resuelve contra un proveedor
real.

**`internal/tuning`**: `Candidate`/`Build` (arma un `BehavioralDecider`
con estado fresco — profiles y baseline de anomaly vacíos por diseño,
ninguna corrida contamina a la siguiente), `Replay` (corre el motor real
sobre un escenario en memoria, sin HTTP), `ComputeDetectionDelay`/
`CampaignDelay`, `SummarizeDelay`, `RunScenario`, y exportación completa a
CSV/JSON/Markdown.

**Campaign key por vector, nunca uniforme.** `ComputeDetectionDelay`
agrupa eventos maliciosos en "campañas" con una regla distinta por vector:
`slow_scan` → una campaña por entidad que escanea (sesión si existe, si no
la IP), igual que lo ve el propio detector; `credential_stuffing` → una
campaña por grupo de red (el mismo resolver simulado que usa el propio
detector) — el detector correlaciona por ASN, nunca por IP individual, así
que medir delay por IP habría sido conceptualmente incorrecto.

**Auditabilidad completa del sweep.** El formato de exportación (`Row`)
está diseñado desde el principio para la comparación completa: una fila
por candidato×seed×ratio, con TP/FP/TN/FN, precision/recall/FPR/FNR/F1
strict y broad, recall por vector, y detection delay — nunca
preagregado, para poder reconstruir después, a partir de las filas crudas,
por qué se habría elegido cada configuración.

**Bug de reproducibilidad encontrado y corregido (en un test, no en
producción).** Un test de reproducibilidad bit-a-bit falló — no en
`Action`/`AttackVector` ni en ninguna métrica, solo en `ConfidenceScore`,
con una diferencia de ~1e-16 (un ULP). Causa raíz: `internal/slowscan`
acumula entropía iterando un `map[string]int]`, y Go aleatoriza a
propósito el orden de iteración de un map entre corridas del proceso, así
que la suma en coma flotante de esos términos puede diferir en el último
bit entre dos corridas con la misma semilla, aunque la lógica sea 100%
determinista. Nunca cambia ninguna decisión real (los umbrales de Policy
están lejísimos de un ULP) — se ajustó el test para comparar lo que
realmente importa (Action/AttackVector/EntityID y las métricas derivadas
de esos campos, que sí son bit-a-bit idénticas) en vez de exigir
igualdad exacta sobre `ConfidenceScore`. No se tocó `internal/slowscan`.

### Resultados del baseline (configuración original, sin ningún cambio)

3 seeds (101/102/103) × 3 ratios (0/10/30%) = 9 corridas, ~1100-1750
eventos cada una:

| Seed | Ratio | Strict TP/FP/FN/TN | Broad TP/FP/FN/TN | Recall CS | Recall SS | CS delay (campañas/detectadas/req.medio) | SS delay |
|---|---|---|---|---|---|---|---|
| 101 | 0% | 0/0/0/1183 | 0/41/0/1142 | N/A | N/A | — | — |
| 101 | 10% | 23/0/115/1183 | 121/30/17/1153 | 0.842 | 0.890 | 1/1/4.0 | 2/2/1.0 |
| 101 | 30% | 32/0/486/1183 | 228/23/290/1160 | 0.872 | 0.254 | 1/1/6.0 | 9/9/5.33 |
| 102 | 0% | 0/0/0/1134 | 0/76/0/1058 | N/A | N/A | — | — |
| 102 | 10% | 30/0/98/1134 | 114/65/14/1069 | 0.977 | 0.847 | 1/1/2.0 | 2/2/2.5 |
| 102 | 30% | 0/0/487/1134 | 292/33/195/1101 | 0.961 | 0.436 | 1/1/6.0 | 9/8/6.38 |
| 103 | 0% | 0/0/0/1178 | 0/47/0/1131 | N/A | N/A | — | — |
| 103 | 10% | 11/0/137/1178 | 127/33/21/1145 | 0.957 | 0.812 | 1/1/3.0 | 2/2/8.0 |
| 103 | 30% | 1/0/571/1178 | 253/24/319/1154 | 0.948 | 0.225 | 1/1/6.0 | 9/6/21.33 |

Los cuatro errores concretos de este baseline (falsos positivos de
`statistical_anomaly`, `strict_recall` casi inexistente por
`BlockThreshold`, degradación de `slow_scan`, estabilidad de
`credential_stuffing`) se analizan en detalle en las secciones 6, 8, 5 y 4
respectivamente — cada uno motivó el proceso de calibración específico de
ese componente.

### Sweep combinado: atribución cruzada entre detectores

**Infraestructura.** `ComputeMitigationAttribution`: para cada evento
mitigado de un vector, clasifica si disparó su propio detector, si también
disparó `statistical_anomaly`, si dependió únicamente de `anomaly`, o si
fue una señal cruzada.

**Resultados agregados (promedio de 3 seeds), combinando candidatos de
`slow_scan` y `statistical_anomaly`:**

| Candidato | FPR@0% | BroadRecall@30% | Precision@30% | F1@30% | Recall CS@30% | Recall SS@30% |
|---|---|---|---|---|---|---|
| C0 baseline (S0+A0) | 0.0472 | 0.4940 | 0.9067 | 0.6361 | 0.9267 | 0.3050 |
| C1 slowscan-only (S3+A0) | 0.0472 (=) | 0.6757 | 0.9297 | 0.7757 | 0.9267 (=) | 0.5669 |
| C2 slowscan+account-weight (S3+A3) | 0.0384 | 0.7503 | 0.9468 | 0.8292 | 0.8985 | 0.6862 |
| C3 slowscan+trigger020 (S3+A2) | 0.0350 | 0.6303 | 0.9566 | 0.7545 | 0.9267 (=) | 0.5013 |

**Contraste C2 vs. C3.** Falsos positivos: C3 levemente mejor (FPR 0.0350
vs 0.0384) — diferencia del orden de la variabilidad normal entre seeds.
Recall general (broad@30%): C2 claramente mejor (0.750 vs 0.630). Recall
credential_stuffing@30%: C3 no tiene ningún costo (0.9267, igual que
baseline) — C2 cuesta ~3 puntos (0.8985), y ese costo, según el hallazgo
de atribución cruzada documentado en la sección 4, es específicamente la
asistencia de `statistical_anomaly` a `credential_stuffing` volviéndose un
poco menos frecuente, no el propio detector correlacionado empeorando.
Recall slow_scan@30%: C2 gana con claridad (0.686 vs 0.501, +18.5 puntos)
— la métrica que motivó todo este sweep. **Lectura, sin elegir
automáticamente:** C2 era la opción más fuerte para el objetivo original
de este sweep (recall de slow_scan) y para recall general, a cambio de un
costo chico y mecánicamente explicado en credential_stuffing y una FPR
apenas mayor; C3 era la opción "no tocar credential_stuffing bajo ninguna
circunstancia", pero dejaba gran parte del problema original de slow_scan
sin resolver. Finalmente se aprobó continuar con S3+A3 (equivalente a C2)
como base de la calibración de credential_stuffing (sección 4) y,
después, de Policy (sección 8).

### Holdout final: Baseline original vs. configuración final calibrada

**Contexto.** Con la configuración completamente congelada (checkpoint
pre-holdout creado en el commit `6abed47`), se corrió holdout por primera
y única vez: seeds 201/202/203, ratios 0/10/30%, comparando el baseline
original (sin ningún cambio) contra la configuración final calibrada
(credential_stuffing `CSw2`, slow_scan `S3`, statistical_anomaly `A3`,
Policy Challenge=0.50/Block=0.75, ScoreFloor sin tocar) — y, para medir
generalización, la misma comparación recalculada también sobre tuning con
exactamente esta configuración final (no reutilizando números de reportes
previos con otra Policy).

**Resultado — Final vs. Baseline, dentro de holdout (pooled 3 seeds):**

| Ratio | Métrica | Baseline | Final |
|---|---|---|---|
| 0% | FPR (broad) | 0.0529 | 0.0617 |
| 10% | Precision / Recall / F1 (broad) | 0.7116 / 0.8479 / 0.7738 | 0.7182 / 0.9549 / 0.8198 |
| 10% | Recall (strict/BLOCK) | 0.0535 | 0.2648 |
| 30% | Precision / Recall / F1 (broad) | 0.9468 / 0.4842 / 0.6407 | 0.9621 / 0.8837 / 0.9213 |
| 30% | Recall (strict/BLOCK) | 0.0070 | 0.3578 |
| 10%/30% | CS RecallDetector | 0.0000 / 0.6060 | 0.1148 / 0.8517 |
| 10%/30% | SlowScan RecallDetector | 0.6298 / 0.1494 | 0.6298 / 0.5577 |

Final sigue superando a Baseline en holdout en prácticamente todas las
métricas de cobertura — el patrón observado en tuning se reproduce.

**Generalización: tuning vs. holdout, candidato Final:**

| Ratio | Métrica | Tuning | Holdout | Lectura |
|---|---|---|---|---|
| 0% | FPR (broad) | 0.0381 | 0.0617 | Peor en holdout (signo invertido vs. Baseline) |
| 10% | Recall (broad) | 0.9203 | 0.9549 | Generaliza bien (incluso mejor) |
| 10% | Recall (strict) | 0.4179 | 0.2648 | Peor en holdout |
| 10% | CS RecallDetector | 0.2304 | 0.1148 | Cae a la mitad — CSw2 calibrado con solo 3 seeds |
| 10% | SlowScan RecallDetector | 0.7045 | 0.6298 | Generaliza razonablemente |
| 30% | Recall (broad) | 0.7559 | 0.8837 | Generaliza bien (mejor) |
| 30% | Recall (strict) | 0.3855 | 0.3578 | Generaliza razonablemente |
| 30% | CS RecallDetector | 0.8515 | 0.8517 | Generaliza casi perfecto |
| 30% | SlowScan RecallDetector | 0.4758 | 0.5577 | Generaliza bien (mejor) |
| 30% | F1 (broad) | 0.8403 | 0.9213 | Generaliza bien (mejor) |

**Lectura general.** La mayoría de las métricas de cobertura (Broad
Recall, F1, SlowScan RecallDetector, CS RecallDetector@30%) generalizan
bien o incluso mejoran en holdout — sin señal de overfitting ahí. La
señal de generalización más débil está concentrada en dos lugares
concretos, ambos coherentes con limitaciones ya documentadas antes de
correr holdout: CS RecallDetector@10% (detalle en sección 4) y FPR@0%/los
3 falsos BLOCK (statistical_anomaly, baseline global, detalle en secciones
6 y 8). Ninguna de las dos fue una sorpresa cualitativa — son exactamente
los dos riesgos que se habían anticipado y documentado como limitaciones
antes de ver estos resultados.

**Estabilidad entre seeds.** En holdout, Final es más estable que en
tuning para BroadRecall (Range 0.030-0.079 vs. 0.113-0.316 en tuning) y
para FPRBroad (0.035-0.074 vs. 0.039-0.044) — pero menos estable para
StrictRecall a 10% (Range 0.349 en holdout vs. 0.050 en tuning).

**Limitaciones documentadas, confirmadas con evidencia de holdout.**
Detectores/features con estado: cada corrida (tuning y holdout) parte de
estado limpio por diseño, así que la comparación es justa — pero en
producción real el estado persiste indefinidamente, algo que ningún
holdout de este tipo puede medir. El resto de las limitaciones
confirmadas por holdout está documentado en el detalle de cada detector
(secciones 4, 6 y 8).

**No se propuso ningún threshold nuevo a partir de estos resultados** —
detector config, Policy y ScoreFloor permanecieron exactamente como se
habían congelado en el checkpoint pre-holdout.

## 11. Rendimiento

### Infraestructura: microbenchmark y load test HTTP

**Problema.** Medir el rendimiento del motor (latencia de decisión pura y
throughput HTTP end-to-end) antes de considerar cualquier optimización,
sin cambiar ningún detector/threshold/Policy/ScoreFloor — la detector
layer usada es exactamente la del checkpoint pre-holdout (secciones 4, 5,
6 y 8).

**Parte A — Microbenchmark (`internal/engine/decide_bench_test.go`).**
`go test -bench=. -benchmem`, tres perfiles (`LegitOnly`/`Mixed`/
`AttackHeavy`, ratio 0/10/30%), cada uno con un decider fresco propio
construido con la configuración final congelada y un resolver
determinista.

**Ajuste de timestamps monotónicos.** `monotonicEventStream` preserva el
patrón real de deltas entre eventos consecutivos dentro de cada vuelta del
escenario, pero en el borde entre una vuelta y la siguiente (donde el
delta real sería negativo: último evento → primer evento) usa el delta
promedio del escenario — así el timestamp queda siempre estrictamente
creciente a lo largo de toda la corrida, sin que la segunda vuelta cruce
eventos como "tardíos" contra el watermark que los detectores ya
alcanzaron en la primera.

**Parte B — Load test HTTP end-to-end (`internal/loadtest` +
`cmd/loadtest`).** `cmd/loadtest` arma los 3 perfiles una vez (semilla
dedicada 901, nunca la de tuning ni la de holdout), y por cada combinación
(perfil × concurrencia × modo OTel) corre repeticiones con servidor fresco
sobre la configuración final congelada.

**Cursor atómico compartido.** Un único `int64` atómico compartido entre
todos los workers de una repetición — `request n -> events[n %
len(events)]` — nunca cada worker recorriendo el escenario desde el evento
0 por su cuenta. Verificado con un test dedicado: con 5 eventos y
concurrencia 4, los 5 aparecen repartidos de forma pareja. Los timestamps
se reescriben a `time.Now()` en cada envío — **documentado explícitamente
como *serving-performance testing*, no comparable con la precisión de
detección de tuning/holdout** (la compresión temporal invalida las
ventanas deslizantes).

**ASN determinista en el load test.** `--asn-mode=simulated` (default)
usa el mismo resolver determinista del tuning — ejercita la correlación
real de credential_stuffing sin tocar la red. Nunca `"ripestat"` en este
comando.

**Repeticiones y agregación.** `--reps=3` por default, cada una con
decider/servidor frescos. `Aggregate` reporta throughput como mediana +
min/max entre las 3 repeticiones (nunca un promedio simple — un test
prueba explícitamente que un conjunto asimétrico {10,10,100} da mediana
10, no el promedio engañoso 40) y latencias p50/p95/p99. La matriz OTel
comparativa queda acotada a `mixed@25` y `mixed@100`, ON vs. los mismos
puntos OFF ya corridos en la matriz principal — nunca duplica toda la
matriz.

**Etiquetado explícito de lo que mide el load test.** El reporte llama a
los resultados HTTP "local end-to-end / loopback throughput" — nunca
capacidad absoluta de un servidor separado, cliente y servidor comparten
proceso y máquina — y al delta de memoria "proceso combinado
cliente+servidor", nunca RAM exclusiva del servidor.

**Smoke test antes de la corrida real.** Se verificó el harness con una
corrida chica de sanity antes de correr la matriz completa, sin ejecutar
ninguna optimización — medir primero fue un requisito explícito del
proceso.

### Correcciones al harness, antes de la matriz completa

Seis correcciones sobre el harness ya implementado, todas verificadas con
tests nuevos, antes de correr la matriz completa — cero cambios de
detección/thresholds/ScoreFloor/Policy.

**`wiring.FinalConfigs()`/`FinalPolicy()` como única fuente de verdad.**
Detallado en la sección 1 — cerró la brecha entre lo que `cmd/engine`
servía por defecto y la configuración que el load test necesitaba medir.

**Percentiles: mediana de percentiles por repetición, nunca pool.** El
diseño anterior mezclaba las muestras crudas de las 3 repeticiones en un
pool único antes de percentilar. La corrección calcula el percentil por
repetición y reporta la mediana de esos tres percentiles como P50/P95/P99
del agregado. Test explícito: dos repeticiones con P50 propios de 10ms y
20ms dan P50 agregado 15ms (mediana), nunca 10ms (lo que daría el pool de
las 4 muestras crudas).

**HTTP client/transport: keep-alive y pool dimensionado para la
concurrencia.** `loadtest.NewClient(concurrency)` arma un
`*http.Transport` propio (nunca `http.DefaultTransport`, cuyo
`MaxIdleConnsPerHost=2` de fábrica fuerza a reabrir conexión TCP en casi
cada request bajo concurrencia alta, midiendo el costo de abrir
conexiones en vez del costo real de servir) — `MaxIdleConns`/
`MaxIdleConnsPerHost` mayor o igual a la concurrencia pedida (mínimo 256),
keep-alive habilitado. Un cliente por repetición, compartido entre todos
sus workers.

**Warmup/measurement: separación estructural, no solo condicional.** `Run`
se reescribió en dos fases de código físicamente separadas (fase de
warmup sin grabación, después fase de medición con grabación, con su
propio reloj de referencia) — antes era un único loop con una condición
"si el timestamp es posterior a X, grabar", que funcionaba pero dependía
de esa condición nunca fallar. Ahora es estructuralmente imposible que una
muestra de warmup llegue a un resultado. Test explícito: un servidor que
tarda 200ms en responder, con Warmup=50ms/Measurement=400ms — el único
request de warmup, aunque su respuesta llega bien entrada la ventana de
medición nominal, nunca se cuenta.

**Entorno: OS/versión, arquitectura, CPU, RAM, Go version, GOMAXPROCS.**
`detectEnv()` agrega, vía `os/exec` (sin dependencias nuevas), la versión
exacta del SO y la RAM total, con fallback silencioso a
"desconocido"/0 si el comando no está disponible (nunca bloquea la
corrida por esto).

**OTel: comparación pareada, cercana en el tiempo.** El comparativo OTel
ya no corre todo OFF (como parte de la matriz principal) y todo ON al
final (con el resto de la matriz de por medio) — para cada uno de los dos
puntos de interés (`mixed@25`, `mixed@100`), corre OFF×3 repeticiones
inmediatamente seguido de ON×3 repeticiones, cerca en el tiempo. Estas
filas se marcan como comparación pareada y se reportan en una tabla
separada de la matriz principal.

### Medición real de performance

**Microbenchmark** (`go test -bench='BenchmarkDecide' -benchmem
-count=3`):

| Perfil | ns/op (3 reps) | B/op | allocs/op |
|---|---|---|---|
| LegitOnly | 9737/9843/9884 | ~16868 | 45 |
| Mixed | 9804/9792/9914 | ~16408 | 45 |
| AttackHeavy | 10251/10471/10316 | ~16835 | 46 |

**Matriz HTTP completa (15 combinaciones: 3 ratios × 5 concurrencias, OTel
OFF).** Cero errores en las 45 combinaciones (15 puntos × 3 reps).
Throughput sube fuerte de concurrencia 1→10, sigue subiendo despacio hasta
50, y se aplana (o cae levemente) de 50→100 en los tres perfiles —
saturación entre concurrencia 25 y 50 en la máquina de prueba (8 cores
compartidos entre cliente y servidor en el mismo proceso). p95/p99 crecen
aproximadamente lineal con la concurrencia una vez saturado (firma de
cola, no de un cuello de botella puntual).

### Hallazgo sin causa atribuida: attack-heavy más rápido en HTTP pese a ser más caro en el microbenchmark

El tráfico attack-heavy mostró un throughput HTTP local aproximadamente
20–27% mayor que el tráfico exclusivamente legítimo, pese a ser
aproximadamente 5% más caro en el microbenchmark aislado del motor de
decisión. El análisis offline no encontró ninguna explicación de soporte
basada en tamaño de request, tamaño de response, cardinalidad de
entidades ni diversidad de rutas. Por lo tanto, no se afirma ninguna
explicación causal. Este resultado se trata como un comportamiento
dependiente de la carga de trabajo del benchmark local por loopback, no
como evidencia de que el tráfico malicioso sea intrínsecamente más barato
de procesar.

**Verificación (diagnóstico offline, seed 901, sin HTTP, sin repetir la
matriz).** El tamaño de request resultó prácticamente idéntico entre
perfiles (270-286 bytes de media); el tamaño de response de attack-heavy
fue el más alto de los tres (527.7 bytes de media, p50=707 — 30.7% de sus
decisiones son CHALLENGE/BLOCK con `ContributingSignals`/`Explanation`,
contra 7.1%/12.6% en normal/mixed) — predeciría lo contrario de lo
observado; la cardinalidad de IPs (151 vs 62) y la diversidad de paths (48
vs 19) también son mayores en attack-heavy, y tampoco explican una ventaja
de velocidad. Ninguna de las variables offline disponibles respalda la
diferencia observada — no se afirma causa, y no se abrieron experimentos
adicionales para investigarlo más a fondo.

### Comparativo OTel pareado — dos corridas

**Primera corrida** (measurement=10s, mismo momento que la matriz
principal): mixed@25 Δthroughput=+0.27%, Δp95=-0.84%, Δp99=-1.66%;
mixed@100 Δthroughput=-0.84%, Δp95=+0.90%, Δp99=+0.43%.

**Segunda corrida, de verificación** (measurement=35s — para que una
corrida ON incluya varios ciclos completos del exportador de ~15s, no solo
uno — solo estos 4 puntos, matriz principal no repetida): mixed@25
Δthroughput=-0.27%, Δp50=-0.41%, Δp95=+1.49%, Δp99=+4.20%; mixed@100
Δthroughput=-0.25%, Δp50=+0.24%, Δp95=-0.07%, Δp99=+1.17%. Cero errores en
las 4 combinaciones × 3 repeticiones.

Todos los deltas, en las dos corridas, están por debajo del 5% y sin una
dirección consistente entre métricas — comparables a la variabilidad
normal entre repeticiones ya observada en la matriz principal (hasta ~9%
de spread en algunas combinaciones). **No se observó overhead material de
OpenTelemetry bajo las condiciones locales probadas** — nunca "sin
overhead" ni "cero overhead", que sería una afirmación más fuerte de lo
que estos datos permiten.

### Verificación

Los reportes (`microbench.txt`, `loadtest.csv`, `loadtest.json`,
`summary.md`) documentan explícitamente el hallazgo de attack-heavy sin
causa atribuida y la conclusión de OTel con la redacción exacta descrita
arriba. No se usó pprof. No se optimizó nada. No se cambió ningún
detector/threshold/Policy/ScoreFloor/harness durante esta fase.

## 12. Escalabilidad

### Escalado conceptual a 1.000 millones de requests/hora

**Alcance.** Documento puramente conceptual (`docs/scaling-1b-rph.md`, con
su versión Mermaid en el README), sin ninguna implementación: no se agregó
infraestructura distribuida, ninguna dependencia nueva, y no se modificó
ningún detector/threshold/Policy/ScoreFloor del proyecto actual. Se
planificó primero en conversación (problema en lenguaje simple,
arquitectura de dos caminos, componente por componente, flujo paso a
paso, comparación con el proyecto actual) y se ajustó en tres puntos antes
de escribir el documento final.

**1. "Risk Cache" renombrado a "Risk State Store", con una aclaración
explícita.** No es un caché de decisiones `ALLOW` fijas — es un valor de
riesgo dinámico que cualquier detector puede actualizar en cualquier
momento; un `ALLOW` no es una promesa de seguridad futura, es "sin
evidencia hasta ahora". Esta distinción es consistente con la semántica ya
establecida para `Decision` en el proyecto actual (sección 8): la
decisión siempre refleja evidencia real, la acción es una consecuencia de
esa evidencia en el momento de evaluarla, no una garantía permanente.

**2. Limitación de cold-start agregada explícitamente (sección 4 del
documento).** Una entidad nueva no tiene historia conductual, así que sus
primeras requests pasan mientras se acumula evidencia — conectado
directamente con el *detection delay* ya medido empíricamente en tuning y
holdout (mediana ~24-26 requests para credential stuffing, ~3-10 para
slow scan, según candidato/ratio — ver sección 10). Se aclara que
distribuir la arquitectura no agrega ni elimina este cold-start — solo lo
preserva, siempre que la partición (por ASN/IP-sesión/cohorte) sea la
correcta.

**3. High Availability reescrita con fail-open/fail-closed explícito por
componente (sección 5 del documento).** Tabla componente por componente, y
una subsección dedicada a la caída del Risk State Store con una propuesta
de degradación controlada: la Blocklist se sigue consultando aparte;
default `CHALLENGE`, no `ALLOW`/`BLOCK`, durante la caída; alertas
inmediatas; alta disponibilidad real del propio store como primera línea
de defensa. El trade-off disponibilidad vs. seguridad queda documentado
explícitamente, nunca escondido detrás de un genérico "default seguro" —
un enfoque consistente con la decisión de fail-open ya tomada para
observabilidad (sección 9), donde un fallo de un componente secundario
nunca frena el servicio de seguridad, pero aplicado aquí con el criterio
inverso cuando el componente que falla es central para la decisión misma
(el propio Risk State Store), no periférico.
