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

## 2026-09-24 — Mezclador de escenarios: 0%, 10% y 30% (tarea 0.6)

**Cómo se calcula el volumen malicioso, sin forzar el porcentaje
exacto.** Primero se genera toda la población legítima (incluidos los
tenants sobre el ASN de hosting, ver más abajo) y se cuenta cuántos
eventos produjo de verdad (`L`) — no se adivina de antemano, porque
cada sesión genera un número de eventos que depende del azar. Con `L`
conocido, se calcula el volumen malicioso objetivo
(`M = L · ratio / (1 - ratio)`) y se reparte entre los dos ataques: el
credential stuffing recibe como máximo el 30% de ese volumen
(`StuffingShareOfMalicious`), reflejando que es, por diseño, un ataque
de bajo volumen — no se infla artificialmente para "completar" el
porcentaje. El escaneo lento absorbe el resto. **No se recorta ningún
evento a mitad de una sesión para ajustar el número exacto** — eso
rompería la coherencia narrativa de una sesión. En cambio, se calcula
el porcentaje real alcanzado (exacto, porque el ground truth se
conoce) y se guarda en `manifest.json`. Con la población por defecto y
semilla 42: 8.85% real para el objetivo de 10%, y 28.51% real para el
objetivo de 30% — ambos dentro de la tolerancia de ±3 puntos
porcentuales que se dejó como criterio (verificado por test).

**Simplificación respecto del plan original: los dos volúmenes de
ataque se estiman en paralelo, no en dos pasadas.** En la
planificación se había propuesto generar primero el stuffing, medir su
volumen real, y recién ahí calcular cuánto escaneo hace falta para
completar el resto. En la implementación se simplificó: los dos
volúmenes se estiman a la vez, a partir de promedios esperados
(intentos por IP, requests por escáner) — es más simple de razonar y
la diferencia práctica es chica, porque ambos promedios son
razonablemente estables con las cantidades de esta tarea. Queda
anotado acá porque es una desviación consciente del plan aprobado, no
un olvido.

**`ProfileHostedTenant`: mismo comportamiento que `ProfileAPIClient`,
construido a partir de él, no copiado a mano.** Se define como una
función que toma `ProfileAPIClient`, le cambia el `Name` y el `Pool` a
`PoolHostingSim`, y devuelve el resultado — así, si mañana se ajusta
algún parámetro de `ProfileAPIClient` (probabilidades, rutas), el
tenant hereda el cambio automáticamente, sin tener que actualizar dos
lugares.

**Direcciones disjuntas entre tenants legítimos y atacantes, mediante
un sorteo coordinado — no por probabilidad baja de choque.** Antes de
generar los ataques, se sortean primero las IPs de los tenants
legítimos (`PoolHostingSim.DistinctAddrs`), y recién después las IPs
atacantes se sortean con el nuevo método `DistinctAddrsExcluding`
(agregado en `ipspace.go`), que nunca devuelve una dirección ya usada
por los tenants. Se evaluó la alternativa de sortear ambos conjuntos
por separado y aceptar una probabilidad chica de superposición, pero
con las cantidades de esta tarea (8 tenants, hasta 150 IPs de
stuffing, sobre un pool de 254) el número esperado de choques no era
despreciable — así que se prefirió la garantía exacta, con un método
adicional chico y reutilizable en vez de una probabilidad a
documentar.

**El campo `IPs` en `CredentialStuffingCampaign` y en `SlowScanProfile`
es opcional y no rompe nada de la tarea 0.5.** Si es `nil` (el caso de
todos los tests ya existentes), el comportamiento es idéntico al de
antes: cada generador sortea sus propias direcciones. El mezclador de
esta tarea es el único que lo usa, para repartir el sorteo coordinado
de arriba. Se corrieron de nuevo los tests de la 0.4 y la 0.5 después
del cambio — todos siguen en PASS.

**No se asume que una IP tiene una única etiqueta — la evaluación
siempre se hace por `request_id`.** La garantía de direcciones
disjuntas de este escenario es una simplificación deliberada para
tener un primer dataset limpio de evaluar, no una regla general del
proyecto. Queda anotado para más adelante: una extensión natural es
generar a propósito un escenario donde una misma IP mezcle tráfico
legítimo y malicioso (por ejemplo, un usuario real detrás de un proxy
que en otro momento participó, sin saberlo, de una botnet), y
confirmar que el mecanismo de evaluación —que ya cruza por
`request_id`, nunca por entidad— sigue funcionando igual de bien en
ese caso.

**Formato de archivos: dos JSONL más un manifiesto, por escenario.**
`events.jsonl` (exactamente `LabeledEvent.Payload()`, sin ninguna
etiqueta — es lo único a lo que tiene acceso el código que arma el
request hacia el motor), `labels.jsonl` (`request_id` + `label`, el
ground truth) y `manifest.json` (semilla, configuración y
estadísticas, sin ninguna marca de tiempo real de generación, para que
el manifiesto también sea reproducible byte a byte). Verificado por
test que `events.jsonl` y `labels.jsonl` tienen exactamente el mismo
conjunto de `request_id` — ni de más, ni de menos.

**`cmd/datagen`** es el ejecutable nuevo: `--seed`, `--ratio` (0, 10 o
30) y `--out`. Los objetivos `make data-0`, `make data-10`,
`make data-30` y `make data-all` (agregados al `Makefile` reservado
desde la tarea 0.1) lo invocan con la semilla 42 por defecto. La
carpeta `data/` sigue ignorada por git desde la tarea 0.1.

**Ventana del escenario: 6 horas simuladas**, elegida para contener
cómodamente la ventana de 3 horas del stuffing (con margen antes y
después) y las sesiones de escaneo lento (hasta 3 horas cada una) —
verificado por test que ningún evento de ataque cae fuera de la
ventana del escenario. Esto le deja margen de sobra al futuro motor,
con sus ventanas de tiempo configurables (minutos para correlacionar
stuffing, horas para el escaneo lento), para operar sobre un solo
archivo de escenario.

## 2026-09-24 — El evaluador: `internal/eval` (tarea 0.7)

**Alcance de esta tarea, confirmado antes de implementar:**
`Evaluate` recibe `[]decision.Decision` en memoria — no lee ningún
archivo `decisions.jsonl` todavía. Esa lectura, junto con el
ejecutable `cmd/eval` y el reporte en Markdown, queda para la tarea
0.8. Tampoco se implementó el motor WAF ni la API HTTP.

**`internal/eval` es, junto con `internal/datagen`, el único paquete
del proyecto que importa `internal/groundtruth`.** Vale la pena
tenerlo claro para la entrevista: la regla de aislamiento de la tarea
0.2 nunca fue "nadie puede ver el ground truth" — fue "el motor nunca
lo ve". El evaluador existe precisamente para comparar el ground
truth con las decisiones; verlo es su trabajo, no una excepción a la
regla.

**Cada métrica revisa su propio denominador, de forma independiente —
no hay una regla del tipo "en el escenario de 0% todo es N/A".**
Corrección importante hecha antes de implementar: `Precision` depende
de cuántas veces el motor predijo positivo (`TP+FP`); `Recall` y
`FNR` dependen de cuántos positivos reales había (`TP+FN`); `FPR`
depende de cuántos negativos reales había (`FP+TN`). Son tres
condiciones distintas. En el escenario de 0% de tráfico malicioso,
`TP+FN` siempre es 0 (no hay ningún ataque real), así que `Recall` y
`FNR` son N/A — pero si el motor bloqueó aunque sea un evento
legítimo por error, `TP+FP > 0` y `Precision` SÍ está definida (va a
dar 0%, porque ese positivo predicho fue un falso positivo). Cada uno
de los dos casos tiene su propio test
(`TestConfusionMatrix_Metrics_PrecisionDefinedWithoutPositives` y su
espejo, `..._RecallDefinedWithoutPredictedPositives`).

**Ninguna métrica indefinida se disimula con un 0 o un 1.** El tipo
`Ratio` (`{Value float64; Defined bool}`) obliga a que quien lea el
resultado compruebe explícitamente si el número tiene sentido, en vez
de asumirlo.

**Dos políticas, siempre las dos, nunca una a elección.** Estricta
(solo `BLOCK` es positivo) y amplia (`CHALLENGE` o `BLOCK`) — porque
un `CHALLENGE` es una molestia mucho más barata que un `BLOCK`, y
evaluar solo con la política estricta penalizaría injustamente a un
motor que contiene el ataque con fricción baja en vez de bloquear
directamente.

**Recall separado por `credential_stuffing` y `slow_scan`, pero
Precision y FPR siguen siendo globales.** Un falso positivo (molestar
a un usuario legítimo) no "pertenece" a ningún tipo de ataque en
particular, así que desglosarlo por tipo no tendría sentido — solo el
recall (¿de los ataques de este tipo, cuántos atrapé?) se desglosa.

**Atribución del vector de ataque: tres categorías, no dos, y solo
sobre los verdaderos positivos.** Correcto / Desconocido / Incorrecto
— nunca se mezcla "desconocido" con "incorrecto": un motor que dice
honestamente `unknown` cuando no está seguro no debería penalizarse
igual que uno que afirma un vector concreto y se equivoca. La
precisión de atribución (`Correct / (Correct + Incorrect)`) deja
`Unknown` fuera del denominador — y si un motor siempre responde
`unknown`, esa precisión es N/A, no 0% (verificado por test). Esto
solo se evalúa entre los verdaderos positivos de la política amplia:
no tiene sentido preguntar "¿acertó el vector?" sobre un falso
positivo (no hay ningún ataque real con el cual comparar) ni sobre un
evento que ni siquiera se marcó.

**Integridad de datos: cuatro problemas detectados, ninguno frena el
cálculo, pero todos quedan marcados.** `request_id` duplicado en las
etiquetas, `request_id` duplicado entre las decisiones, etiqueta
desconocida, decisión faltante y decisión sobrante. Las decisiones
faltantes o sobrantes se **excluyen** del cálculo de la matriz de
confusión (no se puede contar una acción que no existe, y tratar una
decisión faltante como un `ALLOW` implícito escondería posibles bugs
del motor). `Issues.Clean()` es la señal explícita de que un
resultado es un diagnóstico parcial, no definitivo — el criterio que
pediste ("no permitir que un reporte con decisiones faltantes se
interprete como resultado definitivo") queda resuelto acá: cualquier
código que lea un `Result` tiene que comprobar `Clean()` antes de
darlo por bueno, no puede ignorarlo.

**Evaluación por entidad o por campaña: documentada como trabajo
futuro, no implementada.** Esta tarea mide únicamente por
`request_id`, que es la unidad natural de `Decision`. Queda anotado
para más adelante: una campaña de credential stuffing distribuido
puede involucrar cientos de IPs, y — como ya vimos en la tarea 0.6 —
una IP compartida no necesariamente tiene una única etiqueta (un
mismo cliente podría, en un dataset más realista, mezclar tráfico
legítimo y malicioso). Por eso la evaluación por entidad, si se
construye en el futuro, tiene que seguir agregando sobre etiquetas
por `request_id` — nunca asumir que "esta IP = este resultado". El
campo `EntityID` que ya tiene `Decision` alcanza para construir esa
métrica más adelante sin tener que tocar el contrato.

**Motores ficticios, solo dentro de los tests.** `decideAllowAll`,
`decideBlockAll` y `decidePerfectOracle` viven únicamente en
`evaluate_test.go` — no son código de producción, existen para
confirmar que el propio evaluador es confiable antes de usarlo contra
un motor real: "permitir todo" tiene que dar recall 0%, "bloquear
todo" tiene que dar FPR 100%, y el "oráculo perfecto" (que hace
trampa mirando la etiqueta — algo que ningún motor real puede hacer)
tiene que dar 100% en todo.

**Prueba de extremo a extremo con datos reales de la tarea 0.6.** Se
generó un escenario del 10% con `datagen.BuildScenario`, se escribió
a un directorio temporal con `datagen.WriteScenario`, y se aplicó una
regla de juguete construida **únicamente a partir de `events.jsonl`**
(nunca mirando `labels.jsonl`) para simular decisiones de un motor.
Sobre 1.292 eventos reales, la tubería completa (cargar, cruzar,
calcular) corrió sin errores y con los números internamente
consistentes (el total de cada matriz de confusión coincide con la
cantidad de eventos cruzados). No mide si la regla es buena — mide
que el evaluador funciona sobre datos con la forma real, no solo
sobre los 7 a 15 casos armados a mano.

## 2026-09-24 — Ejecutable de evaluación y reporte Markdown: `cmd/eval` (tarea 0.8)

**Alcance.** `cmd/eval` es la puerta de entrada por archivo del
evaluador de la tarea 0.7: lee `labels.jsonl` y `decisions.jsonl` de
una carpeta de escenario, corre `eval.Evaluate` (sin duplicar ningún
cálculo — `EvaluateDecisions` es una envoltura fina, ver más abajo) y
genera un reporte Markdown legible. Sigue sin existir ningún motor
WAF, ninguna API HTTP: `decisions.jsonl` es siempre un archivo que
alguien (hoy, un motor ficticio de test) generó aparte.

**Carga de decisiones: tres categorías de problema, no dos.**
`LoadDecisions` (`internal/eval/decisions.go`) separa cada línea de
`decisions.jsonl` en tres resultados posibles:

1. Decisión utilizable (JSON válido, `request_id` no vacío, pasa
   `decision.Validate()`).
2. `InvalidIDs`: JSON válido y `request_id` identificable, pero la
   decisión no pasa `decision.Validate()` — por ejemplo, un `BLOCK`
   sin `Explanation` ni `ContributingSignals`. Se identifica por su
   `request_id`.
3. `CorruptLines`: la línea no se pudo interpretar en absoluto — JSON
   inválido, o JSON válido con `request_id` vacío. No hay ningún ID
   confiable para identificarla, así que se reporta por número de
   línea (1-indexado).

Ninguna de las dos categorías de problema entra al cálculo de
métricas, y ninguna se convierte silenciosamente en un `ALLOW`
implícito — es el requisito explícito que pediste. `decision.Validate`
se reutiliza tal cual (tarea 0.3): `LoadDecisions` no reimplementa
ninguna regla de validación semántica, solo decide qué hacer con el
resultado.

**Evitar reportar el mismo problema dos veces.** Si la única decisión
de un `request_id` es inválida, `Join` (tarea 0.7) no tiene forma de
distinguir "nunca llegó ninguna decisión" de "llegó una decisión
inválida y se descartó" — sin ajuste extra, ese `request_id`
terminaría apareciendo tanto en `InvalidDecisionIDs` como en
`MissingDecisionIDs`, contando el mismo problema con dos nombres.
`EvaluateDecisions` (`internal/eval/evaluate.go`) corrige esto
después de llamar a `Evaluate`: quita de `MissingDecisionIDs`
cualquier `request_id` que ya esté en `InvalidDecisionIDs`, dejando el
diagnóstico más preciso (`InvalidDecisionIDs`) como único registro del
problema. Probado en
`TestEvaluateDecisions_InvalidDecisionIsExcludedNotAllow`.

**`Issues` creció, pero `Clean()` sigue siendo la única señal a
comprobar.** Se agregaron `InvalidDecisionIDs` y
`CorruptDecisionLines` a la struct `Issues` de la tarea 0.7, y
`Clean()` los incluye en su chequeo — cualquier código que ya
comprobaba `Clean()` sigue funcionando sin cambios, ahora con una
cobertura más completa de problemas.

**Reporte Markdown: nunca disimula un N/A, nunca esconde una
advertencia.** `RenderMarkdown` (`internal/eval/report.go`) es una
función pura que solo formatea un `eval.Result` ya calculado — no
recalcula ninguna métrica. Reutiliza `Ratio.Defined` de la tarea 0.7
para imprimir literalmente `N/A` en vez de un `0.000` cuando un
denominador es cero (la misma regla, ahora expuesta en el texto que
lee un humano). Si `Issues.Clean()` es `false`, el reporte abre con
un bloque de advertencia (⚠️, en negrita, con la lista completa de
problemas) **antes** de mostrar cualquier matriz o métrica — probado
explícitamente en `TestRenderMarkdown_DirtyResult_ShowsWarningAndLists`,
que confirma que la advertencia aparece antes que las secciones de
política.

**`cmd/eval/main.go`: tres códigos de salida, no dos.**

- `0` (`exitClean`): reporte generado, sin problemas de integridad.
- `1` (`exitIntegrityIssues`): el reporte SÍ se generó — el comando
  hizo su trabajo — pero `Issues.Clean()` es `false`. No es un error
  operativo: es información sobre la calidad del dato de entrada.
- `2` (`exitOperationalError`): el comando no pudo completar su
  trabajo — archivo inexistente, fallo de lectura o escritura.

Separar estos dos últimos casos importa porque un script (o vos, a
mano) necesita poder distinguir "esto no corrió" de "esto corrió pero
avisa que el dato está incompleto" sin tener que parsear el texto del
reporte.

Flags: `--scenario` (obligatorio, carpeta con `labels.jsonl` y
`decisions.jsonl`) y `--out` (opcional; si se omite, el reporte se
imprime por stdout en vez de escribirse a disco).

**Pruebas.** `internal/eval/decisions_test.go` (carga de decisiones
válidas, JSON corrupto, `request_id` vacío, decisión semánticamente
inválida, líneas en blanco ignoradas — usando el fixture
`testdata/eval/decisions_sample.jsonl`, con los cinco casos a
propósito), `internal/eval/evaluate_decisions_test.go` (decisión
inválida excluida sin duplicar el problema, líneas corruptas ensucian
`Clean()`, y una comprobación defensiva explícita de que
`TP+FP+FN+TN` coincide exactamente con `TotalJoined` en las dos
políticas, incluso con decisiones inválidas o corruptas de por
medio), `internal/eval/report_test.go` (reporte limpio sin
advertencia, reporte sucio con la advertencia y las listas, y un
escenario totalmente en cero donde cada métrica tiene que salir
`N/A`), y `cmd/eval/main_test.go` (prueba de extremo a extremo de
`run()` — la función interna que arma `main`, sin invocar el binario
como subproceso, para que el test sea rápido — con un escenario chico
limpio, uno sucio, un directorio sin archivos, y el caso sin `--out`
imprimiendo a stdout). Todos los motores y datasets usados son
ficticios, construidos solo para el test.

**Makefile.** Se agregó el target `eval`, parametrizado con
`SCENARIO` y `OUT` (por defecto `data/scenario-0` y
`reports/scenario-0.md`), análogo a los targets `data-*` de la tarea
0.6. No se corrió contra ningún escenario real todavía: sin motor,
`decisions.jsonl` no existe para ningún escenario generado por
`cmd/datagen`, así que no hay nada real que evaluar todavía — el
target queda listo para cuando exista.

## 2026-09-24 — Línea base de rate limiting por IP: `internal/baseline` (tarea 0.9)

**Qué es y qué NO es.** `internal/baseline` es un rate limiter
tradicional por IP, con ventana deslizante — la técnica de
mitigación más simple y más común contra tráfico abusivo. Su único
propósito es servir de punto de comparación conocido, medido sobre
los mismos escenarios y con el mismo `cmd/eval`, contra el que se va
a comparar el motor conductual de la Fase 1. El nombre del paquete
(`baseline`, no `engine` ni nada parecido) es deliberado, para que
nunca se confunda con el detector real del challenge. Nunca importa
`internal/groundtruth` — decide únicamente con lo que ve en
`event.Event`, la misma separación que ya exigía la tarea 0.2 para
cualquier detector real.

**Dos modos de conteo, sin duplicar la identificación de rutas de
login.** `Config.Mode` puede ser `"all"` (cuenta toda petición de la
IP) o `"auth"` (cuenta únicamente las peticiones que
`event.AuthPathMatcher` reconoce como ruta de autenticación —
reutilizado tal cual de la tarea 0.2, sin ninguna lógica nueva de
reconocimiento de rutas). En modo `"auth"`, una petición que no es de
login siempre es `ALLOW` y ni siquiera entra al conteo de ninguna IP:
modela un rate limiter específico de `/login`, la forma más común en
la práctica de mitigar credential stuffing.

**Ventana deslizante, no de bloques fijos.** Para el evento actual
(timestamp `t`, IP `X`), se cuentan las peticiones contadas de `X`
con timestamp en el intervalo cerrado `[t-Window, t]` — que siempre
incluye al propio evento actual. Se eligió deslizante en vez de fija
(“se resetea cada minuto en punto”) porque una ventana fija tiene un
hueco conocido: un atacante puede mandar el límite completo justo
antes de que cierre una ventana y el límite completo otra vez apenas
abre la siguiente, duplicando el volumen real en segundos sin que
ningún contador lo vea. La implementación usa una cola por IP
(`map[netip.Addr][]time.Time]`) que se recorta por adelante (lo que
ya salió de la ventana) y crece por atrás (el evento actual) — costo
amortizado bajo por evento, sin recorrer el historial completo de
cada IP en cada petición.

**Validación explícita, nunca un reloj real.** `Config.Validate()`
exige `MaxRequests > 0` y `Window > 0`, y `Detect` además exige que
`events` venga ordenado por `Timestamp` de forma no decreciente —
si no lo está, devuelve `ErrEventsOutOfOrder` en vez de calcular
algo sin sentido sobre una entrada desordenada. El único reloj que
existe es `event.Event.Timestamp`, igual que en el resto del
proyecto desde la tarea 0.4.

**Acciones: solo ALLOW y BLOCK, vector siempre `unknown`.** Sin
`CHALLENGE` — un rate limiter tradicional de referencia tiene
tradicionalmente un único umbral binario, y mantenerlo así simplifica
la comparación contra la política estricta del evaluador. El
`AttackVector` de toda decisión `BLOCK` es `AttackVectorUnknown`: un
conteo de peticiones por IP no tiene ninguna forma de distinguir
credential stuffing de escaneo — ambos "se ven" igual (muchas
peticiones). Esta limitación de atribución es intencional y es
justamente parte de la comparación contra el motor conductual.

**`ConfidenceScore`: revisado, ya no satura de entrada.** La primera
versión del plan proponía `min(count/MaxRequests, 1.0)`, que con el
doble del límite ya da `1.0` y no distingue más entre el doble y las
cien veces el límite. La fórmula final es `1 - MaxRequests/count`
(solo para `BLOCK`; `ALLOW` siempre tiene `ConfidenceScore = 0`):

```
count = MaxRequests+1 (recién se cruzó el límite) → score ≈ 0
count = 2×MaxRequests                             → score = 0.5
count = 10×MaxRequests                             → score = 0.9
count → ∞                                          → score → 1 (nunca lo toca)
```

Sigue siendo, como ya advertía `decision.Decision.ConfidenceScore`
desde la tarea 0.3, una heurística legible — cuántas veces se superó
el límite —, NO una probabilidad estadísticamente calibrada de que
el tráfico sea un ataque.

**`decisions.jsonl` compatible con `cmd/eval`, sin tocar las tareas
0.7/0.8.** `cmd/baseline --scenario ... --mode ... --max-requests ...
--window ...` lee `events.jsonl` y escribe un `decisions.jsonl` con
el mismo contrato que ya consume `cmd/eval`. Como `Detect` siempre
devuelve exactamente una decisión por evento de entrada, el archivo
resultante nunca genera decisiones faltantes/sobrantes al cruzarlo —
confirmado en `TestDetect_IntegratesWithEval`. Para evitar pisar
resultados al probar distintos modos/umbrales, `--out` por defecto
arma un nombre que incluye el modo, el umbral y la ventana (ej.
`decisions-baseline-auth-max5-win5m0s.jsonl`); como `cmd/eval` sigue
esperando el nombre exacto `decisions.jsonl` dentro de `--scenario`
(no se tocó su lógica), evaluar una corrida puntual requiere pasarle
`--out <scenario>/decisions.jsonl` explícitamente — el propio
`cmd/baseline` lo recuerda en su último log.

**Calibración: semilla distinta a la del reporte, y una predicción
escrita antes de correr el número.** Se generaron datasets de
calibración con `--seed 1` (`data-calibration/scenario-10` y
`scenario-30`, jamás comprometidos al repo — ver `.gitignore`),
separados de los datasets de reporte que ya usa el proyecto desde la
tarea 0.6 (`--seed 42`, en `data/scenario-*`). El umbral se eligió
mirando *solo* los datos de calibración, y recién después se corrió,
ya fijo, contra los datos de reporte — para que el número final no
haya "memorizado" las particularidades de la corrida que se muestra.

Antes de correr nada, la predicción explícita (ya escrita en el plan
aprobado) era: esta línea base tiene que verse mal contra el
credential stuffing distribuido de baja intensidad de la tarea 0.5
(150 IPs con 1-3 intentos cada una, repartidos en una campaña de 3
horas) — por diseño, ningún umbral razonable de "peticiones por IP en
una ventana corta" puede cruzarse con esos números.

Barrido sobre `scenario-10`/`scenario-30` de calibración, política
estricta, `MaxRequests` ∈ {2, 3, 5, 10, 20, 50, 100, 200} y `Window`
∈ {60s, 300s, 600s}, en los dos modos:

- **Modo `all`:** con umbrales laxos (≥20 en 60s) nunca bloquea nada
  (Recall=0%, FPR=0%) — el tráfico legítimo del generador (sobre
  todo `ProfileNavegante` trayendo varios recursos estáticos
  seguidos) igual nunca llega a esos volúmenes por IP en tan poco
  tiempo, así que tampoco lo hacen los ataques. Con umbrales
  ajustados (≤10 en 60s) empieza a haber falsos positivos —FPR de
  6% a 80% según el umbral— sin que el recall suba nunca de 0%: el
  tráfico legítimo "en ráfaga" (fetch de assets, clústeres de
  oficina compartiendo IP) dispara el límite antes que ningún
  ataque, porque ambos ataques están diseñados para ser de baja
  intensidad por IP.
- **Modo `auth`:** FPR = 0.000 en absolutamente todos los umbrales
  probados (nadie más que los intentos reales de login entra al
  conteo, y `ProfileNavegante`/`ProfileAPIClient` casi nunca
  reintentan login) — pero Recall = 0.000 también en todos los
  umbrales probados: la campaña de credential stuffing de la tarea
  0.5 nunca manda más de 3 intentos de login por IP en 3 horas,
  muy por debajo de cualquier umbral probado incluso en la ventana
  más ancha (600s). El escaneo lento, además, ni siquiera pasa por
  `/login` la mayoría de las veces, así que el modo `auth`
  estructuralmente no puede tocarlo.

**Configuración final elegida:** `mode=auth, max-requests=5,
window=300s` (5 minutos) — un valor de referencia habitual para rate
limiting de login en la práctica (similar al recomendado por OWASP
para políticas de bloqueo de intentos), y la única combinación que en
la calibración nunca generó un falso positivo. Se aplicó, sin
cambios, contra los tres escenarios de reporte (`data/scenario-0/10/30`,
semilla 42). Resultado real medido:

```
scenario-10 (política estricta): TP=0 FP=0 FN=121 TN=1246 — Precision=N/A Recall=0.000 FPR=0.000 Accuracy=0.911
  por vector: credential_stuffing TP=0 FN=41 Recall=0.000 · slow_scan TP=0 FN=80 Recall=0.000
```

0 BLOCK en los tres escenarios de reporte (0/10/30). Esto no es un
error del baseline ni de la evaluación: es exactamente la predicción
escrita antes de medir. Confirma con datos reales, no solo en teoría,
por qué un rate limit tradicional por IP —incluso bien calibrado, sin
ningún falso positivo— no alcanza contra un ataque distribuido de
baja intensidad, y es la justificación medida (no solo argumentada)
de por qué hace falta el motor conductual de la Fase 1.

**Limitación documentada, no resuelta acá: NAT.** Varias sesiones
legítimas distintas detrás de la misma IP comparten el mismo
contador y pueden terminar bloqueadas entre sí aunque cada una sea
individualmente legítima (`TestDetect_NATManySessions_SameIPStillShared`).
Con el `mode=auth` elegido esto es improbable en la práctica (pocos
intentos de login por sesión), pero sigue siendo una limitación
estructural de cualquier rate limit puramente por IP — el motor
conductual de la Fase 1 va a necesitar señales más finas que la IP
sola (sesión, cuenta probada) para no heredar el mismo problema.

**Tests.** `internal/baseline/ratelimit_test.go`: umbral no
alcanzado, umbral exacto vs. primera petición que lo supera, dos IPs
con contadores independientes, NAT con varias sesiones detrás de la
misma IP, ventana deslizante liberando eventos viejos, determinismo
(misma entrada → misma salida corrida dos veces), modo `all` vs.
modo `auth` contando distinto sobre el mismo tráfico, configuraciones
inválidas (`MaxRequests`/`Window`/`Mode`, individualmente y
combinadas, con `errors.Is`), eventos fuera de orden, y que toda
decisión generada (`ALLOW` y `BLOCK`, en los dos modos) pase
`decision.Validate()`. `internal/baseline/ratelimit_integration_test.go`:
genera un escenario real con `datagen.BuildScenario`, corre
`Detect`, escribe `decisions.jsonl`, y confirma con
`eval.EvaluateDecisions` que el pipeline completo
(generar→detectar→escribir→cargar→cruzar→evaluar) es autoconsistente
(`Issues.Clean()==true`, totales coinciden) — mismo patrón que la
prueba de extremo a extremo de la tarea 0.7.

**Makefile.** Target `baseline`, parametrizado con
`SCENARIO`/`MODE`/`MAX_REQUESTS`/`WINDOW`/`BASELINE_OUT`, análogo a
`eval` y `data-*`.
