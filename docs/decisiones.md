# Diario de decisiones

Registro de las decisiones tomadas durante el challenge: qué se decidió, por
qué, y qué alternativas se consideraron. Sirve como memoria del proyecto y
como material de preparación para la defensa técnica.

## 2026-09-24 — Arranque del proyecto (Fase 0)

**Nombre y ubicación del repositorio.** `waf-behavior-engine`, dentro de
`~/Desktop/M/`, clonado desde el repositorio remoto ya creado en GitHub
(`snelly1903/MeLi-waf-behavior-engine`). El repo llegó vacío salvo el
`README.md` por defecto, que se reemplazó por el esqueleto del proyecto.

**Idioma.** Código, nombres de paquetes, funciones y comentarios en inglés
(convención estándar del ecosistema Go). Documentación (`README.md`,
`docs/`) en español, porque el objetivo del challenge es entender y poder
defender cada decisión, no solo tener el código funcionando.

**Estructura de carpetas.** `cmd/` para los programas ejecutables
(`datagen`, `eval`, y más adelante `engine`) e `internal/` para el código
reutilizable, siguiendo la convención estándar de Go: todo lo que vive bajo
`internal/` no puede ser importado por otro módulo fuera de este repositorio.

**Separación de la etiqueta de verdad (ground truth).** El paquete
`internal/groundtruth` (Fase 0, tarea 0.3) va a contener las etiquetas
`legit` / `credential_stuffing` / `slow_scan`. Ninguna parte del motor de
detección (`cmd/engine`, cuando exista) va a importar ese paquete. Esto se
verifica con un test dedicado, para que la garantía no dependa solo de
disciplina al escribir código sino de que el propio código lo impida.

**Versión de Go.** `go.mod` fija `go 1.23.1`, la versión instalada en la
máquina de desarrollo (Apple M3, 16 GB RAM), que cumple de sobra el mínimo
exigido por el challenge (Go 1.22+).

**Qué se creó en esta tarea (0.1).** `go.mod`, `Makefile` (objetivos
`test`, `fmt`, `vet`), `.gitignore` (excluye `/data/`, binarios y archivos
de macOS/editores) y el esqueleto de `README.md` con el entorno de pruebas
documentado, según lo exige el challenge.

**Qué queda pendiente.** El contrato del evento HTTP y de la decisión
(tarea 0.2 y 0.3), el generador de tráfico con ground truth (0.4–0.6) y el
"árbitro" que mide falsos positivos y falsos negativos (0.7–0.9).

## 2026-09-24 — Contrato del evento HTTP (tarea 0.2)

**Campos obligatorios.** Solo 6: `request_id`, `timestamp`, `client_ip`,
`method`, `path`, `status_code`. Es el mínimo que cualquier fuente de
logs real puede ofrecer y alcanza para construir las señales de ambos
ataques. El detalle completo está en `docs/formato-eventos.md`.

**Método HTTP sin restringir a la lista clásica.** Se valida que sea
sintácticamente correcto (sin espacios, hasta 20 caracteres) pero no se
limita a GET/POST/etc. Un método inusual (`TRACE`, uno inventado) puede
ser una señal de escaneo — decidir eso es trabajo del detector (Fase
1), no de la validación del contrato.

**`client_ip` como `net/netip.Addr`, no como `string`.** Se eligió el
tipo de la librería estándar `net/netip` en lugar de guardar la IP como
texto. Ventajas: una IP mal formada falla al deserializar el JSON antes
de llegar a la validación explícita, las comparaciones y los usos como
clave de mapa (Fase 1, perfiles por IP) no generan asignaciones de
memoria extra, y el tipo expone directamente `IsPrivate()`,
`IsLoopback()` y similares para la regla de "solo IPs públicas".

**ASN fuera del evento.** El ASN no viaja en el contrato: se calcula
después, a partir de `client_ip`, en el componente de enriquecimiento
(Fase 1). Razón: el ASN es un dato sobre la IP en general, no sobre un
request puntual, y su disponibilidad no debe condicionar si un evento
es válido.

**Rutas de autenticación como componente separado
(`AuthPathMatcher`).** Qué ruta es "el login" depende de la aplicación
protegida, no del formato del evento — por eso no es una regla de
validación, sino un matcher configurable aparte
(`internal/event/authpath.go`), con una lista por defecto pensada para
el generador de tráfico.

**Dos tolerancias de tiempo distintas, y por qué no son lo mismo.** La
validación del evento (`Validator`, con `MaxPastAge` = 5 min y
`MaxFutureSkew` = 1 min, ambos configurables) rechaza fechas
claramente rotas — es higiene de datos, corre una sola vez al entrar
el evento. El manejo de eventos tardíos dentro de las ventanas de
tiempo del motor es un mecanismo aparte, todavía no implementado
(Fase 1), con su propia tolerancia, que nunca descarta un evento en
silencio sino que lo cuenta en una métrica. Confundir estos dos
mecanismos fue un riesgo identificado y evitado a propósito.

**Reloj inyectable (`Clock`, con `SystemClock` y `ManualClock`).**
Permite testear reglas de tiempo ("un evento de hace 6 minutos se
rechaza") sin esperar minutos reales, y es el mismo mecanismo que
usará el generador de tráfico para simular horas de ataque en
segundos de ejecución.

**`session_id` con solo espacios no es un error.** Se normaliza a
cadena vacía (`Event.Normalize()`) en lugar de rechazarse — se trata
como si el campo no hubiera venido, ya que muchos clientes legítimos
(apps móviles, API) no tienen sesión.

**`login_user_hash` con forma de hash, nunca el email.** Se valida que
sea una cadena hexadecimal de 32 a 128 caracteres. El nombre de
usuario real nunca se guarda ni se transmite en este contrato —
decisión de minimización de datos, verificada con tests sobre el JSON
serializado.

**Errores de validación como valores centinela unidos con
`errors.Join`.** `Validate` devuelve **todos** los problemas
encontrados a la vez (no solo el primero), y cada regla tiene su
propio error exportado (`ErrEmptyRequestID`, `ErrInvalidStatusCode`,
etc.) comprobable con `errors.Is`. Esto hace que los tests sean
específicos por regla y que un evento roto en varios campos se
diagnostique completo en un solo intento.

**Garantía estructural de que el ground truth no entra al motor.**
Tres capas: (1) el tipo `Event` no tiene ningún campo de etiqueta, (2)
un test por reflexión falla si alguna vez se agrega un campo con
nombre parecido a `label`/`truth`/`attack_type`, (3) un test sobre el
JSON serializado confirma que esas palabras tampoco aparecen en los
datos que viajarían por la red. `internal/groundtruth` (tarea 0.3)
será un paquete separado que el motor nunca importará.

## 2026-09-24 — Contrato de la decisión y del ground truth (tarea 0.3)

**`Decision` en `internal/decision`, simétrica a `Event`.** Contiene
solo el núcleo que el evaluador de la Fase 0 necesita: `request_id`,
`timestamp`, `entity_id`, `action`, `confidence_score` y
`attack_vector`. Los campos adicionales que pide el PDF para el log de
auditoría (`contributing_signals`, la explicación por reglas o por
LLM) se agregan en la Fase 1, cuando exista el motor que los produce —
no tenía sentido definirlos ahora sin nadie que los llene.

**`Action` y `AttackVector` como tipos con método `Valid()`,** en lugar
de validar strings sueltos con un `switch` disperso por el código. El
enumerado y la regla de validez viven en el mismo lugar que el tipo.

**Un solo `entity_id` con prefijo (`ip:...`, `session:...`) en lugar de
dos campos separados** (tipo de entidad + valor). Es más simple de
transportar y de loguear, y alcanza para lo que el árbitro necesita en
esta fase; si en la Fase 1 hiciera falta filtrar por tipo de entidad de
forma más rica, se puede derivar del prefijo sin romper el contrato.

**`LabeledEvent` vive en `internal/groundtruth`, no en `internal/event`.**
Es la única estructura del proyecto que junta un `event.Event` con su
`Label`. La dependencia va en un solo sentido: `groundtruth` importa
`event`, `event` nunca importa `groundtruth`. Es la misma garantía
estructural de la tarea 0.2 (separación de la etiqueta), aplicada ahora
a nivel de paquete completo, no solo de campo.

**`LabeledEvent.Payload()`, no `ToEvent()` (nombre elegido por decisión
explícita).** Devuelve únicamente la parte `Event` de un `LabeledEvent`
— es lo único que el generador de tráfico (tarea 0.4 en adelante) debe
enviarle al motor. Un test (`TestLabeledEvent_Payload_NeverCarriesLabel`)
serializa el resultado de `Payload()` y confirma que ninguna palabra
del vocabulario de etiquetas (`label`, `credential_stuffing`,
`slow_scan`, `legit`) aparece en esos bytes — el mismo estilo de
prueba que ya se usó para `Event` en la tarea 0.2.

**`LabeledEvent.Validate` reutiliza `event.Validator` en lugar de
duplicar sus reglas.** `groundtruth` ya depende de `event`, así que
validar el evento contenido delegando en el `Validator` de la tarea
0.2 evita mantener dos copias de las mismas reglas — si una regla de
validación de evento cambia, `groundtruth` la hereda automáticamente.

## 2026-09-24 — Cierre de la tarea 0.3: ajustes de auditoría, score y aislamiento

Antes de pasar a la tarea 0.4 se revisó `Decision` contra los
requisitos de auditoría del PDF y se corrigió el estilo del test de
aislamiento del ground truth. Cuatro decisiones:

**1. `Decision` ahora cubre el log de auditoría completo, no solo lo
que necesitaba el evaluador.** Se agregaron `ContributingSignal`
(`name`, `value`, `weight`), `ContributingSignals`, `Explanation` (la
explicación determinista, calculada por reglas, síncrona) y
`LLMExplanation` (puntero a string, porque hace falta distinguir tres
estados: "esta decisión no usa LLM", "el LLM todavía no respondió" y
"el LLM respondió esto, incluso si fue un string vacío"). `Decision`
sigue siendo un único tipo — el evaluador simplemente ignora los
campos de auditoría que no usa; no se creó un tipo aparte para no
duplicar la estructura.

**Regla de validación nueva:** `Explanation` y al menos un
`ContributingSignal` son obligatorios cuando `Action` es CHALLENGE o
BLOCK (para ALLOW pueden quedar vacíos). `LLMExplanation` nunca es
obligatorio — es asíncrono y la capacidad todavía ni siquiera está
implementada.

**Documentado, para la Fase 1: la explicación del LLM nunca va a
modificar un log de decisión ya emitido.** Los logs son de solo
anexado (append-only). Cuando el LLM responda (potencialmente
segundos después), se va a emitir un **evento de auditoría separado**
(por ejemplo, del tipo "decision_explanation"), correlacionado con la
decisión original por `RequestID` — o por un `DecisionID` dedicado, si
más adelante resulta que un request puede generar más de una
decisión. Quien audite va a tener que cruzar ambos eventos, no esperar
que el primero cambie.

**2. Pesos de `ContributingSignal`: se valida que sean finitos y no
negativos, no que sumen 1.** `Value` y `Weight` se rechazan si son
`NaN` o infinito (con `math.IsNaN`/`math.IsInf`); `Weight` además se
rechaza si es negativo. No se exige que los pesos de una decisión
sumen exactamente 1 — esa normalización depende de cómo termine
funcionando el algoritmo de combinación de señales (fusión log-odds,
según el análisis general), que todavía no existe. Definirla ahora,
sin el algoritmo, sería adivinar una regla que probablemente haya que
cambiar en la Fase 1.

**3. `ConfidenceScore` se documentó como indicador de riesgo, no como
probabilidad calibrada.** Es un número de 0 a 1 que mide qué tan
fuerte es la evidencia de que la entidad esté llevando adelante el
`attack_vector` inferido — comparable entre decisiones, pero sin
ninguna garantía estadística de que "0.7" signifique "70% de
probabilidad real". La acción (ALLOW/CHALLENGE/BLOCK) sale de cortar
ese score con dos umbrales configurables, que van a vivir en la
configuración del motor (Fase 1), no en este contrato.

**Advertencia documentada sobre el barrido de umbrales:** re-evaluar
decisiones ya guardadas con umbrales distintos es útil como primera
aproximación, pero solo es exacto si las decisiones no afectan el
estado del propio motor — y en la práctica sí lo afectan (un atacante
bloqueado deja de generar los eventos siguientes que un atacante
permitido sí generaría). Para validar de verdad un cambio de política
hace falta **reproducir el tráfico** contra el motor con los nuevos
umbrales, no solo reetiquetar decisiones guardadas. Esto queda anotado
para cuando se diseñe `cmd/eval` a fondo en las tareas 0.7–0.9.

**4. Los tests de aislamiento del ground truth ahora comprueban la
ausencia de claves JSON exactas (`label`, `ground_truth`), no la
ausencia de palabras sueltas en todo el documento serializado.** Se
corrigieron `TestLabeledEvent_Payload_NeverCarriesLabel` (en
`internal/groundtruth/label_test.go`) y
`TestEventJSON_GroundTruthNeverTravels` (en
`internal/event/json_test.go`). Razón: una fuga del ground truth solo
puede entrar como un campo nuevo, así que comprobar la clave exacta es
una verificación precisa; buscar substrings en todo el JSON es una
aproximación que puede dar falsos positivos (un campo legítimo que por
casualidad contenga la palabra) o pasar por alto una fuga con otra
forma.

**El test de privacidad de credenciales
(`TestEventJSON_NeverCarriesCredentialLikeKeys`) se dejó como estaba
a propósito, con la razón documentada en el propio archivo:** una
credencial filtrada no necesariamente entra como una clave nueva,
puede colarse como el *valor* de un campo que ya existe (por ejemplo,
alguien pega una contraseña dentro de `UserAgent` por error) — ahí sí
corresponde buscar por substring. Se dejó anotado, además, que esta
prueba es una red de seguridad con una lista fija de palabras, no una
garantía: la validación, minimización y sanitización real de datos
sensibles en la ingesta y en los logs del motor es trabajo de la Fase
1, todavía no implementado.

## 2026-09-24 — Generador de tráfico: reloj, semilla, IPs y usuarios legítimos (tarea 0.4)

**Reloj: se reutiliza `event.ManualClock`, sin tipo nuevo.** Cada
`GenerateLegitSession` crea internamente su propio `ManualClock`,
arrancado en el `start` que le pasa quien la llama, y lo va avanzando
con saltos aleatorios (`rng.DurationRange`) — no hace falta esperar
tiempo real para simular una sesión de varios minutos.

**Coherencia de tiempo al mezclar sesiones: cada sesión se genera con
su propio reloj interno; el orden global es responsabilidad de quien
mezcla, no de un reloj compartido.** Compartir un único reloj entre
sesiones concurrentes habría complicado el código sin necesidad. En
cambio, `GenerateOfficeCluster` (que sí mezcla varias sesiones —
una por empleado) genera cada una por separado y **ordena el resultado
por `Timestamp` antes de devolverlo**. Se deja documentado que la
tarea 0.6, cuando mezcle sesiones de distintos perfiles y ataques en
un único dataset, tiene que aplicar el mismo principio: generar cada
sesión con su propio horario de inicio y ordenar el conjunto al final,
nunca compartir un reloj entre generadores.

**Aleatoriedad: wrapper `RNG` sobre `math/rand/v2`, con semilla.**
Reutilizado tanto por `legit.go` (esta tarea) como, más adelante, por
los generadores de ataque (tarea 0.5). La reproducibilidad se
verificó comparando el JSON serializado de dos corridas con la misma
semilla — no alcanza con "revisar a ojo" que los números se repiten,
hay que probarlo contra la forma final en la que se va a guardar el
dataset.

**IPs y ASN: se usan los tres bloques reservados para documentación
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), con ASN
simulados en el rango 64512–65534 (privado, RFC 6996).** Antes de
implementar se verificó **empíricamente** (no de memoria) que estos
rangos no activan ninguna de las reglas de "IP privada" del `Validator`
de la tarea 0.2 (`IsPrivate`, `IsLoopback`, `IsLinkLocalUnicast`,
`IsUnspecified` dan `false` para las tres direcciones de prueba) — por
lo tanto **no hizo falta modificar el Validator**. Los ASN asignados a
cada pool (`hosting-sim` = 64512, `residential-sim-a` = 64513,
`residential-sim-b` = 64514) son inventados por este generador; en
ningún lugar del código ni de la documentación se afirma que
pertenezcan a un proveedor real. El enriquecimiento real de IP
(ASN/geo de verdad) se va a integrar en la Fase 1 mediante un
adaptador independiente, que no tiene por qué conocer esta simulación.

Se dejó anotado que, si la tarea 0.5 necesita más direcciones de las
que da un solo /24 (por ejemplo, para simular un clúster de
credential stuffing con cientos de IPs), el candidato natural es sumar
el rango 198.18.0.0/15 (RFC 2544, benchmarking) — también reservado y
sin conflicto con el Validator, pero eso se decide recién cuando haga
falta.

**Tres perfiles legítimos, como datos de un mismo `struct`, no como
código separado por perfil:**

| Perfil | Trampa que cubre |
|---|---|
| Navegante | Caso normal, pero con `BrokenLinkProbability` (algún 404 legítimo) y `LoginRetryProbability` (typo y reintento con la **misma** cuenta) — la diferencia clave con el credential stuffing de la 0.5, donde cada intento prueba una cuenta distinta |
| Cliente API / app móvil | Nunca manda referer ni pide assets estáticos — exactamente lo que buscaría el detector de escaneo lento, pero es tráfico legítimo |
| Oficina (NAT) | Varios empleados, cada uno con su propia sesión, comparten una única IP — trampa para cualquier regla que asuma "mucho volumen por IP = ataque" |

Un único `LegitProfile` con campos (pools de IP, si manda referer, si
pide assets, probabilidades) evita triplicar la misma lógica de
generación — los tres perfiles son instancias del mismo tipo con
valores distintos.

**Validar eventos generados contra `event.Validator`: el reloj de
tolerancia se fija al timestamp del propio evento, no a un "ahora"
externo.** Los eventos generados pueden abarcar minutos u horas
simuladas, mientras que las tolerancias del `Validator` (5 min de
pasado, 1 min de futuro) modelan la ingesta en tiempo real, no la
reproducción de un dataset ya generado. Por eso, en los tests de esta
tarea, cada evento se valida con un `Validator` cuyo reloj está fijado
exactamente en el `timestamp` de ese mismo evento — así se comprueba
lo que sí corresponde acá (forma correcta: IP pública, método válido,
`path` con `/`, status en rango, hash de login bien formado) sin que
la regla de tolerancia de tiempo, pensada para otro escenario, dé un
falso rechazo. Es la misma distinción ya documentada en
`docs/formato-eventos.md` para la tarea 0.2, aplicada ahora a datos
generados en batch.

## 2026-09-24 — Generadores de ataque: credential stuffing y escaneo lento (tarea 0.5)

**Refactor previo: `DefaultLoginPath` compartido.** `legit.go` tenía
`"/login"` repetido como texto suelto en `ProfileNavegante` y
`ProfileOffice`. Se movió a una constante (`paths.go`) reutilizada
también por `GenerateCredentialStuffingCampaign`, así el ataque apunta
al mismo endpoint que navegan los usuarios legítimos, no a una
aplicación simulada distinta. `ProfileAPIClient` mantiene su propio
`"/api/login"` — es, a propósito, un endpoint distinto de la misma
aplicación. Se corrieron de nuevo los tests de la tarea 0.4 después
del cambio: los 8 grupos de tests de `legit.go` siguen en PASS.

**`IPPool.DistinctAddrs`, agregado en `ipspace.go`.** El credential
stuffing necesita `IPCount` direcciones **distintas** (sin reemplazo),
a diferencia de `RandomAddr` (con reemplazo, usado por los perfiles
legítimos, donde una repetición ocasional no importa). Se implementó
con un mezclado Fisher-Yates del espacio de direcciones utilizables
(1 a 254) para que la selección sea uniforme y sin un orden artificial
— no son "las primeras N direcciones del bloque". Entra en pánico si
se piden más de 254: es un error de configuración de la campaña, no
un caso a manejar en tiempo de ejecución. Con `IPCount = 150`, queda
holgadamente dentro del límite de un solo /24.

**Credential stuffing: sondas aisladas, no una sesión.** A diferencia
de `GenerateLegitSession` y de `GenerateSlowScanSession`, acá cada IP
participa con 1 a 3 intentos aislados repartidos al azar en toda la
ventana de la campaña (3 horas simuladas) — no hay una "sesión"
continua por IP, así que no se usa un `event.ManualClock` por IP; cada
timestamp se calcula directo como un desplazamiento aleatorio dentro
de la ventana, y el conjunto completo se ordena al final (mismo
principio de "ordenar al mezclar" que `GenerateOfficeCluster` de la
0.4).

**Cada intento prueba, casi siempre, una cuenta distinta —
`AccountReuseProbability = 5%` en vez de 0%.** Una diversidad de
cuentas del 100% sería una señal *demasiado* limpia — una lista de
credenciales filtrada real suele reciclarse parcialmente entre bots.
Se comprueba con un test que el ratio de cuentas distintas sea alto
(>80%), no exactamente 100%.

**Escaneo lento: rutas mezcladas, no 100% desconocidas.** El 15%
(`ValidPathProbability`) de los requests del escáner apunta a una
ruta real de la aplicación (tomada de `ProfileNavegante.Paths`, no
inventada aparte) en lugar de una ruta del wordlist
(`SensitivePaths`, definido en `paths.go`, verificado por test para
que **nunca** se superponga con ninguna ruta de los perfiles
legítimos). Sobre esas rutas válidas, ~20% lleva parámetros de query
fuzzeados (solo nombres, nunca valores — misma regla de privacidad
del contrato de eventos).

**Los valores numéricos de esta tarea (150 IPs, 1–3 intentos, ventana
de 3 h, 1% de éxito, 5% de reutilización de cuenta; 20–60 requests,
pausas de 20 s a 3 min, 15% de rutas válidas, 20% de fuzzing de
parámetros) son configurables y sirven para generar el dataset de
prueba — no son umbrales de detección.** El motor (Fase 1) va a
definir sus propios umbrales de forma independiente de cómo se generó
este tráfico; confundir "con qué parámetros generé el ataque" con
"con qué umbral lo voy a detectar" sería circular.

**Ocho decisiones para que el tráfico no sea artificialmente fácil de
distinguir** (quedan documentadas acá porque son las que se van a
defender en la entrevista):

1. Tasa por IP tope duro de 3 intentos — ningún rate-limit por IP
   puede verlo nunca, por construcción.
2. Sin ráfagas: los intentos se distribuyen en instantes aleatorios
   de toda la ventana, no juntos.
3. Ruido controlado a propósito (5% de reutilización de cuenta, 1% de
   éxito, 30% de 403 entre los fallos) — un patrón perfectamente
   limpio sería, en sí mismo, una señal artificial.
4. User-Agent mixto (navegador normal y herramientas de script) en
   ambos ataques — ningún UA único alcanza para distinguir todo.
5. El escaneo mezcla rutas nunca vistas (85%) con rutas reales de la
   aplicación (15%) — un escáner 100% desconocido sería trivialmente
   distinguible con una sola regla de catálogo.
6. **La ausencia de `Referer` está compartida a propósito entre
   `ProfileAPIClient` (legítimo, tarea 0.4) y el escaneo lento
   (ataque).** No es un descuido: es una comprobación incorporada al
   propio dataset de que ningún detector futuro va a poder aprobar el
   challenge usando "falta de referer" como única señal — si lo
   hiciera, generaría falsos positivos contra `ProfileAPIClient`, y
   eso se va a medir en la Fase 0.7+.
7. Timing con jitter aleatorio en los dos ataques, nunca intervalos
   constantes.
8. IPs sorteadas de forma uniforme dentro de todo el /24 (Fisher-Yates),
   no en un rango secuencial artificial.

**Notas para trabajo futuro, a partir de tus cuatro observaciones**
(no se implementan en esta tarea — son recordatorios para la 0.6 y la
Fase 1):

- *"No depender exclusivamente del ASN para identificar stuffing"*:
  ya es cierto por diseño — este generador no calcula ni expone
  ninguna lógica de correlación por ASN, eso es responsabilidad del
  detector (Fase 1). Queda anotado que, cuando exista, tendrá que
  combinar la correlación por ASN con el ratio de fallos y la
  diversidad de cuentas — nunca el ASN solo.
- *"Tráfico legítimo que comparta ASN con algunos atacantes"*: hoy
  los perfiles legítimos usan `PoolResidentialSimA/B` y los ataques
  usan `PoolHostingSim` — pools separados. Para la tarea 0.6 (mezcla
  de datasets) queda anotado agregar una variante de tráfico legítimo
  que también salga de `PoolHostingSim` (por ejemplo, una pequeña
  empresa alojada en un proveedor de hosting) — así "esta IP es del
  ASN de hosting" deja de ser, por sí sola, una señal utilizable.
- *"Los 404 legítimos no deben producir bloqueos injustificados"*: ya
  cubierto estructuralmente desde la tarea 0.4 —
  `BrokenLinkProbability` en `ProfileNavegante` y `ProfileOffice`
  genera una tasa de 404 legítima mayor a cero. Queda anotado que la
  medición real de esto (falsos positivos sobre tráfico 100%
  legítimo) es exactamente lo que mide el perfil de prueba "0% de
  tráfico malicioso" en la Fase 0.9 y en la evaluación final.
- *"UA, ruta o ausencia de Referer no deben alcanzar por sí solos"*:
  ya incorporado en el diseño de esta tarea (puntos 4 y 6 de la lista
  de arriba). Queda pendiente, para cuando exista el detector real
  (Fase 1), medir esto de forma cuantitativa con la matriz de
  confusión — hoy es una propiedad del dataset, ahí va a ser una
  propiedad medida del detector.
