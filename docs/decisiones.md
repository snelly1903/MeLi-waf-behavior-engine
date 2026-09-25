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

# Fase 1

## 2026-09-25 — Servicio HTTP mínimo de ingestión y decisión: `cmd/engine` (tarea 1.1)

**Qué es y qué NO es.** Primera pieza de la Fase 1: un servicio HTTP
que recibe un evento por `POST /v1/events`, lo valida y devuelve una
decisión — pero **sin ningún detector conductual todavía**. La
decisión siempre es `ALLOW`, con `AttackVector=unknown`. El objetivo
de esta tarea es la tubería completa (HTTP → validación → decisión),
no la inteligencia — eso es explícitamente trabajo de tareas
posteriores de la Fase 1.

**Tres paquetes nuevos, cada uno con una sola responsabilidad:**

- `internal/engine`: la abstracción `Decider` — `Decide(ctx, event.Event) decision.Decision`
  — y su única implementación de hoy, `AllowAllDecider`. Ningún
  detector real vive acá todavía; cuando exista, va a implementar esta
  misma interfaz.
- `internal/httpapi`: la capa HTTP — decodifica JSON, normaliza y
  valida con `event.Validator` (reutilizado tal cual de la tarea 0.2,
  sin duplicar ninguna regla), y le pasa el evento ya validado al
  `Decider`. No sabe nada de cómo se toma una decisión.
- `cmd/engine`: arma las piezas (`event.NewValidator(event.SystemClock{})`
  + `engine.AllowAllDecider{}` + `httpapi.NewServer(...)`) y levanta
  `http.ListenAndServe`.

**Ninguna incompatibilidad encontrada con los contratos existentes.**
Se revisó `internal/event` y `internal/decision` antes de escribir
código: `event.Event` (con `netip.Addr` en `ClientIP`) y
`decision.Decision` ya se serializan/deserializan en JSON sin
problemas — lo prueban `internal/baseline/io.go` y
`internal/eval/decisions.go`, que hacen exactamente eso contra
archivo desde la tarea 0.8. No se modificó ningún archivo de
`internal/event`, `internal/decision`, `internal/datagen`,
`internal/eval` ni `internal/baseline`.

**`Decider` recibe `context.Context` desde el día uno.**
`AllowAllDecider` no lo usa todavía, pero la interfaz ya lo pide —
para poder propagar después cancelación del cliente HTTP, tracing de
OpenTelemetry, o timeouts de dependencias reales (un store, una
llamada al LLM), sin tener que rediseñar la interfaz ni tocar a cada
implementación existente cuando eso llegue. La capa HTTP pasa
`r.Context()` tal cual. `Decide` deliberadamente no devuelve `error`
todavía: en esta etapa no existe ningún modo de falla real (no hay
ninguna dependencia externa que pueda fallar), así que agregarlo
sería anticipar una necesidad que todavía no existe.

**`Explanation` fijo también en `ALLOW`, por decisión explícita.**
El contrato de `decision.Decision` (tarea 0.3) solo exige
`Explanation` para `CHALLENGE`/`BLOCK` — pero acá se decidió incluirlo
siempre, con un texto fijo y determinista
(`"no behavioral detector is implemented yet; default policy is ALLOW"`),
para que incluso una decisión de `ALLOW` quede auditable desde el
primer día, sin esperar a que exista un motor real.

**Dos códigos de error, según qué falló.** `400 Bad Request` cuando
el body no es JSON válido (`error: "invalid_json"`); `422 Unprocessable Entity`
cuando el JSON es válido pero el evento no pasa
`event.Validator.Validate()` (`error: "validation_failed"`, con el
texto ya combinado por `errors.Join` como `message`, sin desglosar
campo por campo — mantenerlo simple). `405 Method Not Allowed` con
header `Allow` para el método incorrecto. Los tres casos comparten el
mismo formato de cuerpo (`errorResponse{Error, Message}`), para que
quien integre contra esta API tenga un único formato de error que
parsear.

**Límite de tamaño del body.** `http.MaxBytesReader` a 64 KiB en
`POST /v1/events` — un evento es un objeto JSON chico; esto evita que
un body arbitrariamente grande consuma memoria antes de llegar
siquiera a la validación.

**Tests.** `internal/engine/engine_test.go`: `AllowAllDecider.Decide`
produce una `Decision` que pasa `decision.Validate()`, con
`RequestID`/`Timestamp`/`EntityID` derivados correctamente del
evento. `internal/httpapi/server_test.go`, todos con `httptest` (sin
levantar ningún servidor real): evento válido → 200 con una decisión
válida; JSON corrupto → 400; evento inválido (IP privada) → 422 con
el mensaje del validador; método incorrecto → 405 con header `Allow`;
`/healthz` → 200.

**Verificación manual real con `curl`** (además de los tests
automatizados) contra `cmd/engine` corriendo de verdad — confirmó el
mismo comportamiento que los tests, incluyendo un detalle real:
un evento con timestamp fijo del pasado (por ejemplo, de una prueba
escrita minutos antes) es rechazado por `ErrTimestampTooOld` al usar
`event.SystemClock{}` — el mismo comportamiento correcto que ya
garantizaba el `Validator` desde la tarea 0.2, ahora visible en vivo
contra un reloj real en vez de uno simulado.

## 2026-09-25 — Perfiles temporales de comportamiento en memoria: `internal/profile` (tarea 1.2)

**Qué es y qué NO es.** El componente con estado que le va a permitir
al futuro motor "recordar" comportamiento reciente de una IP y, si
existe, de una sesión, dentro de una ventana temporal. Todavía no es
un detector — no decide ninguna acción, solo acumula observaciones y
expone métricas agregadas (`Metrics`) para que un detector futuro las
consuma. No se conectó con `cmd/engine` en esta tarea.

**Corrección importante incorporada antes de implementar: los eventos
NO llegan ordenados.** El diseño original (calcado del recorte por
adelante de `internal/baseline`, tarea 0.9) asumía orden cronológico,
válido ahí porque `datagen` genera `events.jsonl` ya ordenado. Pero
`internal/profile` recibe eventos desde `net/http`, donde dos
requests concurrentes pueden procesarse en cualquier orden respecto a
sus propios `Event.Timestamp`. La corrección: cada clave (IP o
sesión) mantiene un **watermark** — el máximo `Timestamp` visto hasta
ahora para esa clave —, que **nunca retrocede**
(`if obs.timestamp.After(state.watermark) { state.watermark = obs.timestamp }`).
La ventana se interpreta siempre respecto al watermark, nunca respecto
al evento que acaba de llegar: un evento atrasado pero todavía dentro
de `[watermark-Window, watermark]` cuenta; uno anterior a ese corte
nunca se agrega, y tampoco puede "revivir" observaciones que ya habían
expirado, porque el watermark con el que se calcula el corte tampoco
retrocede para él.

**Costo aceptado: `Observe` pasó de O(1) amortizado a O(k).** El
truco de `internal/baseline` (recortar solo por adelante de una cola
ordenada) deja de ser válido si el orden de llegada no está
garantizado — insertar un evento fuera de orden puede dejar la cola
sin ordenar, así que ya no alcanza con mirar el frente. La solución
elegida fue la más simple posible: en cada `Observe`, filtrar toda la
cola de esa clave contra el corte actual (recalculado con el
watermark ya actualizado) y agregar la observación nueva si
corresponde — O(k), con k = observaciones retenidas para esa clave
dentro de la ventana. Se decidió explícitamente priorizar corrección y
simplicidad por sobre preservar la complejidad O(1): para el volumen
de este challenge, k está acotado por cuánto tráfico generó una sola
entidad dentro de una sola ventana (chico incluso en escenarios de
ataque), y una estructura de datos más compleja (por ejemplo, un
árbol balanceado por timestamp para mantener el orden con inserciones
arbitrarias) sería optimizar algo que todavía no es un problema
medido.

**Un solo `Window` por `Store`, confirmado.** Si en el futuro hacen
falta varios tamaños de ventana (por ejemplo, un detector que mira 5
minutos y otro que mira 24 horas), se construyen `Store` independientes,
cada uno observando los mismos eventos. Se descartó pasar un `window`
explícito por cada llamada a `Snapshot` (más flexible) porque abría
un error silencioso: pedir una ventana de consulta más ancha que la
ventana de retención del `Store` daría un resultado truncado sin
ningún aviso.

**`NewStore(window) (*Store, error)`, sin panic.** `window <= 0`
devuelve `ErrInvalidWindow` — mismo patrón que
`baseline.Config.Validate()` de la tarea 0.9, consistente con el resto
del proyecto.

**Qué se retiene por observación, y qué NUNCA se retiene.** Se
retiene únicamente: `timestamp`, `path`, `status_code`,
"tiene o no tiene referer" (nunca su contenido), `login_user_hash`
(ya hasheado desde la tarea 0.2 — nunca un username ni un email en
claro, así que reusarlo acá no agrega riesgo de privacidad nuevo), y
`session_id`. Nunca se retienen: el body del request (nunca existió
en `Event`), `UserAgent`, los valores de `QueryParams` (ni falta
hacían para las métricas pedidas), ni el contenido de `Referer`.

**Dos mecanismos de limpieza, con propósitos distintos.** (1) El
recorte automático en cada `Observe`, determinista y basado
exclusivamente en `Event.Timestamp` — acota el tamaño de la cola de
**cada clave individual**. (2) `Sweep(now, idleTTL)`, manual y
opcional — resuelve lo que el recorte automático no puede: una IP que
mandó un solo request y nunca volvió queda con una entrada residual
en el mapa para siempre, porque nada dispara su limpieza si no llegan
más eventos suyos. "¿Ya pasó suficiente tiempo real sin noticias de
esta entidad?" es deliberadamente la única pregunta de todo este
componente que toca un reloj real — porque es una pregunta operativa
(cuánta memoria se usa), no una pregunta de detección (que siempre
usa tiempo de evento). `Sweep` recibe `now` como parámetro (nunca
`time.Now()` internamente), así que sigue siendo determinista y
testeable; conectarlo a un scheduler real (un ticker en `cmd/engine`)
queda fuera del alcance de esta tarea.

**Concurrencia: un `sync.Mutex` por índice (IP y sesión), no uno
global.** Así una escritura sobre perfiles de IP no bloquea una
lectura de perfiles de sesión. `Snapshot` nunca modifica el mapa —
copia el slice retenido antes de soltar el lock. Confirmado sin
condiciones de carrera con `go test -race` sobre dos escenarios de
escritura concurrente (misma IP desde 200 goroutines; y 10 IPs × 50
goroutines cada una, más una sesión compartida entre todas, para
ejercitar también el mutex del índice de sesiones).

**`Metrics` es siempre una copia propia del snapshot.** El slice de
observaciones se copia en `keyedWindow.snapshot` antes de agregar, y
`aggregate` arma un `PathCounts` nuevo en cada llamada — modificar el
`Metrics` devuelto (incluido su mapa) nunca afecta al estado interno
del `Store` ni a un snapshot posterior. Probado explícitamente en
`TestSnapshotMetrics_PathCountsIsOwnedCopy`.

**Sin interfaz `Profiler` separada todavía.** Mismo criterio que
`engine.Decider` (tarea 1.1): cuando exista el primer detector real
que consuma este `Store`, ese paquete define su propia interfaz
angosta con lo que necesita, en su propio código — no antes, con un
solo consumidor hipotético.

**Tests.** Expiración en orden + borde exacto de la ventana; el caso
explícito de fuera de orden pedido (`10:06 → 10:03 → 09:59`, `Window=5min`,
`Total` esperado 2, watermark siempre en `10:06`); **invariancia
respecto al orden de llegada**
(`TestObserve_OrderInvariance_SameEventsDifferentArrivalOrder`,
agregado tras una revisión): los mismos cuatro timestamps
(`10:00, 10:01, 10:03, 10:06`, `Window=5min`) procesados una vez en
orden cronológico y otra vez en el orden `10:06, 10:00, 10:03, 10:01`
tienen que dar exactamente el mismo resultado — `Total=3` (`10:00`
expira una vez que el watermark llega a `10:06`) y
`WindowStart=10:01`/`WindowEnd=10:06` en los dos casos; confirma que
el recorte inspecciona toda la cola (no solo el frente, como si
estuviera ordenada) y que `WindowStart`/`WindowEnd` salen del
mínimo/máximo timestamp real entre las observaciones, no de la
posición del elemento en el slice; un evento tardío
que no puede revivir datos ya expirados; IPs independientes; sesiones
independientes (incluyendo el caso NAT: una IP con dos sesiones
distintas detrás reporta `DistinctSessions=2`); un evento sin
`SessionID` no crea ninguna entrada de sesión; todas las métricas
calculadas a mano (401/403, 404, cuentas distintas, referer
presente/ausente, conteo por ruta); que `Metrics.PathCounts` sea una
copia propia; una clave nunca observada devuelve `Metrics` vacío, no
error; `Sweep` elimina solo lo inactivo; y los dos tests de
concurrencia con `go test -race` ya descritos.

## 2026-09-25 — Detector de credential stuffing distribuido: `internal/credstuffing` (tarea 1.3)

**Qué es y qué NO es.** El primer detector real del motor. Busca
credential stuffing distribuido de bajo volumen por IP, correlacionando
actividad entre múltiples IPs de un mismo grupo de red dentro de una
ventana. Deliberadamente no depende de que ninguna IP individual
supere ningún umbral — el baseline de la Fase 0
(`internal/baseline`, tarea 0.9) ya demostró con datos reales que esa
técnica falla contra este patrón (recall 0% en los tres escenarios de
reporte). No se conectó con `cmd/engine` en esta tarea; no se integró
ninguna fuente real de ASN.

**Dos paquetes nuevos:** `internal/finding` (el tipo `Finding`,
compartido por todos los futuros detectores) y `internal/credstuffing`
(el detector en sí).

**`Finding` reutiliza `decision.AttackVector` y
`decision.ContributingSignal` tal cual**, sin duplicar esos tipos —
combinar los `Finding` de varios detectores (credential stuffing, y
más adelante slow scan) en un `decision.Decision` va a ser concatenar
listas, no convertir tipos.

**Correlación sin depender del perfil de una sola IP.** El estado no
está indexado por IP ni por sesión (eso ya lo cubre `internal/profile`,
tarea 1.2) — está indexado por **grupo de red**. Cada observación
agrega su IP a un *conjunto*, no a un contador: una sola IP mandando
mil requests solo aporta 1 al conteo de IPs distintas, así que un
flood de una sola IP estructuralmente nunca puede cruzar
`MinDistinctIPs` por sí solo — sale gratis de usar un conjunto, no de
un caso especial en el código. Probado en
`TestEvaluate_SingleIP_ManyAttempts_DoesNotTrigger`.

**`NetworkResolver`: interfaz mínima, definida donde se consume.**
Mismo criterio que `engine.Decider` (tarea 1.1): la interfaz vive en
`internal/credstuffing`, no en quien la vaya a implementar. Los tests
usan un `fakeResolver` (`map[netip.Addr]string`), exclusivamente en
`_test.go` — ninguna API real de ASN se integró; queda para una tarea
posterior.

**IP no resoluble: excluida de toda correlación, deliberadamente
conservador.** Si `Resolve` devuelve `ok=false`, el evento no crea ni
contamina ningún grupo. Se descartó agrupar todo lo "desconocido" en
un único balde global porque mezclaría tráfico legítimo no relacionado
de todo el mundo en una falsa campaña. El costo — un atacante detrás
de una IP no resoluble es invisible para este detector — queda
documentado como limitación explícita, no como bug. Probado en
`TestObserve_UnresolvedIP_ExcludedFromCorrelation`, que además
confirma que las IPs no resueltas no contaminan un grupo real conocido.

**Señales, por grupo de red, dentro de la ventana:** IPs distintas,
cuentas distintas (`login_user_hash`, excluyendo vacío — misma
convención que `internal/profile.Metrics.DistinctAccounts`,
consistencia entre componentes), intentos totales, y ratio de 401/403.
Solo se observan eventos de rutas de autenticación —
`event.AuthPathMatcher` reutilizado tal cual de la tarea 0.2.

**Gate conjuntivo (AND, no un promedio que compensa señales débiles
con fuertes).** `Triggered` exige las CUATRO condiciones a la vez:
`DistinctIPs≥MinDistinctIPs`, `DistinctAccounts≥MinDistinctAccounts`,
`TotalAttempts≥MinAttempts`, `FailedRatio≥MinFailedRatio`. Es la
defensa principal contra falsos positivos: `ProfileHostedTenant`
(datagen, mismo ASN simulado que el pool atacante) puede tener muchas
IPs y muchas cuentas, pero sus logins mayormente tienen éxito — nunca
cruza el umbral de ratio, así que nunca dispara, sin importar
diversidad. Probado en
`TestEvaluate_LegitTenantSharingASNWithAttackers_DoesNotTrigger`, y en
los otros dos casos "parciales" pedidos:
`TestEvaluate_ManyFailuresFewAccounts_DoesNotTrigger` (posible
brute-force de una sola cuenta desde muchas IPs — no es el patrón que
busca este gate) y `TestEvaluate_ManyAccountsFewFailures_DoesNotTrigger`
(login masivo legítimo).

**Corrección aplicada tras la revisión: `RiskScore` nunca puede dar 0
cuando `Triggered` es `true`.** La fórmula original
(`1 - umbral/valor` por señal, promediado) da exactamente 0 en las
cuatro componentes cuando las señales están justo en su umbral — y
sin embargo `Triggered` ya es `true` ahí, porque el gate usa `≥`. Un
detector que disparó no puede reportar riesgo cero: sería
contradictorio para quien lea la decisión. Solución mínima aplicada:
un piso configurable, `ScoreFloor ∈ (0,1)`, estrictamente entre 0 y 1
(validado), con
`RiskScore = ScoreFloor + (1-ScoreFloor)·promedio_ponderado`. Sigue
siendo puramente heurístico — arranca en `ScoreFloor` apenas se cruzan
los cuatro umbrales, y crece hacia 1 (sin tocarlo nunca) cuanto más se
los supera — nunca se presenta como una probabilidad calibrada, misma
advertencia que `decision.Decision.ConfidenceScore` desde la tarea
0.3. Probado explícitamente en
`TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore`:
seis intentos armados a mano para que las cuatro señales caigan
EXACTO en su umbral (5 IPs, 4 cuentas, 6 intentos, ratio 0.5) — el
test confirma `Triggered=true` y `RiskScore` exactamente igual a
`ScoreFloor` (0.2 en la configuración de prueba), ni más ni menos.

**`login_user_hash` vacío.** Cuenta en `TotalAttempts` y en el ratio
401/403, pero nunca se agrega al conjunto de cuentas distintas —
mismo criterio que `internal/profile`. Probado en
`TestEvaluate_MissingLoginUserHash_ExcludedFromAccountSet`.

**Sin umbrales de `CHALLENGE`/`BLOCK` en este detector**, según lo
acordado: ya está documentado desde la tarea 0.3 que esos umbrales son
configuración del *policy* del futuro `engine.Decider`, no de cada
detector — este entrega solo `Triggered` + `RiskScore`.

**Eventos fuera de orden: mismo mecanismo de watermark que la tarea
1.2, reimplementado de forma autocontenida.** Se evaluó explícitamente
extraer un `internal/window` genérico del que dependieran tanto
`internal/profile` como `internal/credstuffing`, y se descartó para
esta tarea: mantener el detector autocontenido evita modificar un
componente ya probado (`internal/profile`) sin necesidad, dado el
cronograma corto del challenge. Si aparece un tercer consumidor de
este patrón, ahí sí conviene extraerlo. Costo aceptado: `Observe` es
`O(k)` (reescanea la ventana completa del grupo en cada llamada), no
`O(1)` amortizado — mismo trade-off ya aceptado y documentado en la
tarea 1.2.

**Concurrencia y limpieza.** Un único `sync.Mutex` (acá alcanza con
uno solo: a diferencia de `internal/profile`, hay un solo índice —por
grupo de red—, no dos). `Evaluate` copia el estado antes de soltar el
lock. `Sweep(now, idleTTL)` por simetría con la tarea 1.2, aunque la
cardinalidad de grupos de red es naturalmente chica (a lo sumo unos
pocos miles de ASN reales), así que el riesgo de crecimiento sin
límite es menor acá que en `internal/profile`. Confirmado sin
condiciones de carrera con `go test -race`
(`TestObserve_ConcurrentWrites_SameGroup`, 60 goroutines con IPs y
cuentas distintas y timestamps deterministas sobre el mismo grupo).

**Ningún umbral final elegido mirando la semilla 42.** Los valores
usados en los tests (`baseConfig`, tarea 1.3) son valores de prueba
elegidos para poder calcularlos a mano, explícitamente documentados
como no-finales. La calibración real contra un dataset separado del
de reporte queda para una tarea posterior, mismo criterio que
`internal/baseline` (tarea 0.9).

**Tests.** Los 16 casos: validación de configuración (tabla, cada
regla individual + combinaciones); campaña distribuida clara que
dispara; el caso del umbral exacto con `RiskScore>0` ya descrito; una
sola IP con muchos intentos que no dispara; tenant legítimo
compartiendo ASN con atacantes que no dispara; muchos 401 con pocas
cuentas que no dispara; muchas cuentas con pocos fallos que no
dispara; eventos fuera de ventana (un lote que dispara, expira, y un
evento posterior aislado ya no dispara); IP no resoluble excluida sin
contaminar un grupo real; `login_user_hash` vacío excluido del
conjunto de cuentas; un evento que no es de autenticación nunca
dispara ni toca estado; concurrencia con `go test -race`; y `Sweep`
elimina solo lo inactivo.

## 2026-09-25 — Detector de escaneo/enumeración lenta: `internal/slowscan` (tarea 1.4)

**Qué es y qué NO es.** El segundo detector real del motor. Busca
escaneo/enumeración lenta de rutas HTTP — un atacante que mantiene una
tasa baja de requests a propósito, para evitar un rate limiter, pero
deja un patrón de exploración acumulado dentro de una ventana. A
diferencia de `internal/credstuffing` (tarea 1.3), esta señal es por
entidad individual (IP y/o sesión), nunca correlacionada entre IPs —
mismo criterio que usa `internal/datagen` para generar este tráfico.
No se conectó con `cmd/engine`.

**Reutiliza `internal/profile.Store` en vez de duplicarlo.** Se
evaluó explícitamente antes de escribir código: `profile.Metrics`
(tarea 1.2) ya cubre `Total`, `DistinctPaths` (`len(PathCounts)`),
`Status404`, `WithReferer`/`WithoutReferer`, por IP y por sesión, con
watermark y `Sweep` ya resueltos. `internal/slowscan` construye un
`*profile.Store` propio (no compartido con otros detectores todavía)
y lo consulta — nada de esa lógica se reimplementó. Lo único que
`profile.Store` no puede dar es la popularidad de una ruta *entre
distintas entidades* (necesaria para `NovelPathRatio`); esa es la
única pieza de estado genuinamente nueva de esta tarea
(`pathPopularity`), autocontenida por la misma razón que
`internal/credstuffing` en la tarea 1.3: es una agregación distinta
(por ruta, no por IP/sesión), no hay nada de `profile.Store` para
reutilizar ahí específicamente.

**Entropía de Shannon normalizada.** `H = -Σp_i·log2(p_i)` sobre la
distribución de `PathCounts`, dividida por `log2(DistinctPaths)` para
que perfiles con distinta cantidad de rutas sean comparables con el
mismo umbral (`RouteEntropy=0` si `DistinctPaths≤1`, por definición —
sin diversidad que medir). Confirmado con dos ejemplos calculados a
mano y verificados en `TestNormalizedEntropy_HandComputed`: 4 rutas
con 1 visita cada una → `1.0` (máxima diversidad); 4 rutas muy
concentradas (`17,1,1,1` sobre 20) → `≈0.424`.

**Novedad de rutas: rareza poblacional, no un catálogo externo.** No
existe ninguna fuente de "rutas reales de la aplicación" en la Fase 1,
y usar la lista `SensitivePaths` de `datagen` sería trampa (es
literalmente el ground truth del generador, y el motor no puede
importarlo). La opción mínima técnicamente correcta con los datos
disponibles: cuántas IPs *distintas*, en todo el tráfico que este
detector observó, pidieron cada ruta dentro de la ventana —
`pathPopularity`, con el mismo mecanismo de watermark ya usado dos
veces antes (tercera implementación autocontenida, ver más abajo).
`NovelPathRatio` = fracción de las rutas distintas de la entidad cuyo
conteo global de visitantes es `≤ MaxVisitorsForNovelPath`. Confirmado
a mano en `TestNovelPathRatio_HandComputed`.

**Gate conjuntivo de cinco condiciones — `WithoutRefererRatio`
deliberadamente afuera.** `Triggered` exige `TotalRequests`,
`DistinctPaths`, `NotFoundRatio`, `RouteEntropy` y `NovelPathRatio`
todos a la vez por encima de su umbral. `WithoutRefererRatio` **nunca**
es parte del gate — solo aporta al `RiskScore`, ponderado. Así, la
ausencia de Referer, sea 0% o 100%, no puede por sí sola cambiar
`Triggered`, porque ni siquiera es una de las condiciones — no por una
regla especial, sino porque estructuralmente no participa. Probado
explícitamente en `TestEvaluate_MissingRefererAlone_DoesNotTrigger`.

El gate se verificó contra cada falso positivo pedido: crawler
legítimo y SPA (`NotFoundRatio` bajo — las rutas existen, dan 200);
cliente API sin Referer con navegación estable (`DistinctPaths`/
`RouteEntropy` bajos — pocos endpoints fijos repetidos); enlaces rotos
ocasionales y tráfico normal con algún 404 (`DistinctPaths` bajo o el
volumen de éxitos diluye el ratio); health checks (una sola ruta
repetida, `RouteEntropy=0`) — cada uno con su propio test.

**Corrección de diseño aplicada durante la revisión: IP y sesión se
evalúan SIEMPRE las dos, nunca "sesión si existe, si no IP".** El
diseño original de la tarea (aprobado inicialmente) evaluaba por
sesión cuando existía y por IP solo como respaldo — con un hueco: un
atacante que rota `session_id` cada pocos requests mantiene cada
sesión individual por debajo de los umbrales, mientras la IP agregada
sí muestra el patrón completo, y ese diseño nunca llegaba a mirarla.

La corrección: `Evaluate` calcula **siempre** el candidato por IP y,
si `e.SessionID != ""`, **también** el candidato por sesión, y
devuelve como máximo un único `Finding`:

- las dos dispararon → gana la de mayor `RiskScore`; en empate exacto,
  gana **sesión**, por ser la entidad más específica (evita atribuir
  el hallazgo a todo un NAT cuando alcanza con señalar la sesión
  concreta) — probado con un empate real y verificado en
  `TestEvaluate_IPAndSessionBothTrigger_ReturnsSingleFinding`;
- solo una disparó → esa;
- ninguna → `Finding{}`.

**Por qué evaluar la IP siempre NO reintroduce el falso positivo del
NAT.** El punto clave: a la IP se le aplica el MISMO gate completo de
cinco condiciones, no una versión relajada. Un NAT de oficina con
varias sesiones legítimas, agregado a nivel IP, tiene muchas rutas
distintas — pero son rutas reales (`NotFoundRatio` bajo), así que
nunca cruza esa condición, sin importar cuánta diversidad sume el
NAT. El escáner que rota sesiones sí cruza esa misma condición a nivel
IP, porque sigue pidiendo rutas del wordlist (404). Es el mismo
mecanismo — el gate de cinco condiciones — el que distingue ambos
casos, no una regla especial para NAT. Probado en
`TestEvaluate_ScannerRotatingSessions_DetectedByIP` (dispara por IP,
ninguna sesión individual lo hace) y
`TestEvaluate_LegitNATMultipleSessions_DoesNotTrigger` (varias
sesiones legítimas agregadas en una IP no disparan).

**Limitación honesta documentada, no resuelta acá:** si una IP tiene,
a la vez, tráfico legítimo de un NAT y un atacante real enumerando
rutas, el `Finding` a nivel IP puede terminar asociado también a
algún evento de un usuario legítimo de esa misma IP — mismo trade-off
ya aceptado para cualquier señal a nivel IP (`internal/baseline`,
tarea 0.9). Lo que esta solución sí evita es el falso positivo cuando
nadie malicioso está presente.

**Pendiente explícito para la tarea 1.5, anotado en el código
(`internal/slowscan/detector.go`, tipo `scope`) y acá:**
`finding.Finding` sigue sin ningún campo estructurado para indicar qué
entidad (IP o sesión, y cuál) originó un hallazgo — hoy esa
información solo vive, en texto libre, dentro de `Explanation`
(`"ip:203.0.113.7: ..."` o `"session:s-9f2a: ..."`). El futuro
`engine.Decider` va a necesitar esto de forma estructurada, no
parseando texto, para poder correlacionar varios detectores sobre la
misma entidad o auditar decisiones. Se mantuvo `Finding` sin campos
nuevos en esta tarea, según lo acordado — esta es la anotación
explícita de la deuda, para resolverla cuando `engine.Decider` la
necesite de verdad, no antes.

**`RiskScore`: mismo mecanismo de piso que la tarea 1.3.** Seis
componentes (los cinco del gate + `WithoutRefererRatio`, que solo
aporta al score), combinados en un promedio ponderado
(`ScoreWeights`, normalizado por su suma) con el mismo piso
`ScoreFloor ∈ (0,1)` estricto. Probado con un caso construido a mano
donde las cinco señales del gate caen EXACTO en su umbral (incluyendo
`MinRouteEntropy=1.0`, el máximo posible, y `WithoutRefererRatio=0`
para que el promedio dé exactamente 0) —
`TestEvaluate_AllSignalsExactlyAtThreshold_TriggersWithPositiveScore`
confirma `Triggered=true` y `RiskScore` exactamente igual a
`ScoreFloor`.

**Eventos fuera de orden: mismo mecanismo de watermark, tercera
implementación autocontenida.** Igual que se decidió en la tarea 1.3,
se evaluó extraer un `internal/window` genérico y se descartó de
nuevo por la misma razón (mantener el cronograma corto, no arriesgar
componentes ya probados) — con tres implementaciones independientes
del mismo patrón ahora (`internal/profile`, `internal/credstuffing`,
`internal/slowscan`), la extracción queda como una limpieza cada vez
más razonable para una tarea futura, pero sigue sin ser necesaria hoy.

**Ningún umbral final elegido mirando la semilla 42.** Los valores de
`baseConfig` en los tests son valores de prueba para poder calcularlos
a mano, explícitamente no-finales — la calibración real queda para
una tarea posterior, mismo criterio que `internal/baseline` e
`internal/credstuffing`.

**Tests.** Los 20 casos: validación de configuración; escaneo lento
claro que dispara; volumen concentrado en una sola ruta que no
dispara; muchas rutas legítimas con pocos 404 que no disparan;
muchos 404 sobre pocas rutas repetidas que no disparan; cliente API
sin Referer con navegación estable que no dispara; ausencia de
Referer sola que no dispara; escaneo con gaps grandes que sí se
acumula dentro de una ventana suficientemente ancha; eventos fuera de
ventana dejan de contribuir; invariancia ante eventos fuera de orden;
evento sin `session_id` cae a IP; entropía calculada a mano; novedad
calculada a mano; el caso de umbral exacto con `RiskScore>0`; los tres
tests nuevos de IP+sesión ya descritos; concurrencia con
`go test -race`; y `Sweep` elimina solo lo inactivo.

## 2026-09-25 — `engine.Decider` real: `BehavioralDecider` (tarea 1.5)

**Qué es y qué NO es.** `POST /v1/events` deja de depender de
`engine.AllowAllDecider` — `cmd/engine` ahora arma un
`engine.BehavioralDecider`, que alimenta `internal/credstuffing` e
`internal/slowscan` con cada evento, combina la evidencia que
produzcan y aplica una `Policy` configurable para decidir
`ALLOW`/`CHALLENGE`/`BLOCK`. Sin anomaly detection general, sin LLM,
sin ASN real, sin OTel/Grafana/k6/AWS, sin calibración final contra la
semilla 42 — todo eso sigue fuera de alcance.

**Deuda de la tarea 1.4 resuelta: `finding.Finding` ahora tiene
`EntityID string`.** Mismo formato de prefijo que
`decision.Decision.EntityID` desde la tarea 0.3 (`"ip:..."`,
`"session:..."`, y nuevo: `"network:..."` para credential stuffing).
**Sin `EntityType` separado** — se analizó explícitamente y se
descartó: `decision.Decision` nunca tuvo uno, usa el mismo prefijo
desde el día uno, y `BehavioralDecider` nunca necesita ramificar sobre
el tipo de entidad, solo copiar el `EntityID` de la evidencia
principal. `internal/credstuffing` e `internal/slowscan` ahora
producen este campo estructuradamente, y sus `Explanation` se
simplificaron (ya no repiten el scope en texto, que ahora sería
redundante con `EntityID`).

**`internal/engine/policy.go`: `Policy{ChallengeThreshold, BlockThreshold}`**,
validando `0 ≤ ChallengeThreshold < BlockThreshold ≤ 1`. Los dos
límites son inclusive (`score ≥ BlockThreshold → BLOCK`,
comprobado primero; si no, `score ≥ ChallengeThreshold → CHALLENGE`;
si no, `ALLOW`). Los umbrales viven acá, nunca en un detector
individual — reconfirmado, no nuevo (ya documentado desde la tarea
0.3 y aplicado en 1.3/1.4).

**`FinalRiskScore = máximo entre los `Finding` disparados` — nunca se
suman ni se promedian.** Cada detector mide algo distinto con su
propia escala heurística; sumarlos inventaría un número sin
significado. El principal (mayor score) determina `AttackVector`,
`EntityID` y la explicación central.

**Empate exacto: gana `credential_stuffing`, regla fija y
documentada.** La evidencia de credential stuffing distribuido exige
corroboración entre múltiples IPs independientes (el gate de la tarea
1.3) — una forma de evidencia estructuralmente más difícil de disparar
por casualidad que el patrón de una sola entidad que mira
`internal/slowscan`. Probado con un empate genuino, construido a mano
con las nueve señales del gate de los dos detectores exactamente en su
umbral (`TestDecide_ExactTie_CredentialStuffingWins`): ambos dan
`RiskScore = ScoreFloor = 0.2` exacto, gana `credential_stuffing`.

**`Decision.ContributingSignals` = solo las del finding principal.**
Se evaluó concatenar las señales de todos los detectores que
dispararon, y se descartó: los `Weight` de cada detector están
normalizados dentro de su propio modelo de score — mezclarlas haría
parecer que son parte de un único modelo ponderado, cuando son dos
sistemas de puntaje independientes. Si un segundo detector también
disparó (con menor score), se lo menciona en una frase corta dentro de
`Explanation` — auditable, sin mezclar listas de señales de
proveniencia distinta.

**Semántica consistente para "disparó pero queda en `ALLOW`".** La
`Decision` siempre refleja la evidencia real observada
(`AttackVector`, `ConfidenceScore`, `EntityID`, señales); `Action`
refleja qué se hizo con esa evidencia. Son preguntas distintas. Si
**algún** `Finding` disparó, aunque el score no alcance
`ChallengeThreshold`, la `Decision` conserva el vector, el score real
(no 0), el `EntityID` del principal y sus señales — nunca se tiran
solo porque la acción terminó en `ALLOW`. Válido contra
`decision.Validate()` (tarea 0.3): esos campos nunca están prohibidos
en `ALLOW`, solo no son obligatorios. Solo cuando **ningún** detector
disparó cae al default "nada que reportar"
(`AttackVector=unknown`, score `0`, `EntityID="ip:"+client_ip` — misma
convención que `AllowAllDecider` desde la tarea 1.1). Probado en
`TestDecide_FindingBelowChallengeThreshold_StaysAllowButPreservesEvidence`.

**Flujo verificado contra el código real, no asumido:**
`credstuffing.Observe` → `slowscan.Observe` → `credstuffing.Evaluate`
→ `slowscan.Evaluate` → selección del principal → `Policy`. El orden
entre los dos detectores entre sí no importa (no comparten estado); el
de `Observe` antes que `Evaluate`, para el mismo evento, sí — mismo
contrato de dos pasos que ya exigían por separado `internal/credstuffing`
e `internal/slowscan`.

**`cmd/engine`, credential stuffing sin ASN real:
`credstuffing.UnavailableNetworkResolver`.** Tipo nuevo, de
**producción** (no el `fakeResolver` de ningún test) — `Resolve`
siempre devuelve `ok=false`, así que, por la propia regla de
`internal/credstuffing.Observe` (tarea 1.3), ninguna IP entra jamás a
ninguna correlación: el detector queda estructuralmente inerte pero
corriendo de verdad (`Observe`/`Evaluate` se llaman en cada evento).
Se evaluaron tres alternativas: (1) este resolver placeholder — la
elegida; (2) un `*credstuffing.Detector` nulable en
`BehavioralDecider`, tratado como "desactivado" — descartada, obliga a
chequeos de `nil` en cada punto de uso, con riesgo de panic si alguno
se olvida; (3) reutilizar el `fakeResolver` de los tests — descartada
explícitamente, sería un fake de test terminando en producción.
Reemplazar por un resolver real, cuando exista un proveedor, es
cambiar una sola línea en `cmd/engine/main.go`, sin tocar
`BehavioralDecider`.

**Concurrencia: sin lock nuevo.** `BehavioralDecider` no agrega
ningún estado mutable propio — solo dos punteros a detectores (ya
seguros para concurrencia, tareas 1.3/1.4) y un `Policy` (value type
inmutable). `Decide` es seguro para llamadas concurrentes porque sus
dependencias ya lo son. Confirmado con `go test -race`
(`TestDecide_Concurrent_NoRaces`).

**Sin interfaces nuevas para los detectores.** Se evaluó una interfaz
angosta (`Observe`/`Evaluate`) para poder inyectar dobles de test en
`BehavioralDecider`, y se descartó: hoy hay una sola implementación de
cada ataque, y los tests arman escenarios reales con umbrales
pequeños — mismo patrón que ya probó ser suficiente en las tareas 1.3
y 1.4. Habría sido sobrearquitectura para un solo consumidor.

**Tests.** `internal/engine/behavioral_test.go` (17 tests): validación
de `Policy` (tabla) y sus dos bordes exactos probados directamente
sobre `actionFor` (`score` exactamente en `ChallengeThreshold` y en
`BlockThreshold`); construcción inválida de `BehavioralDecider`;
ningún detector dispara → `ALLOW`; finding bajo `ChallengeThreshold`
preserva evidencia; sobre `ChallengeThreshold` → `CHALLENGE`; sobre
`BlockThreshold` → `BLOCK`; `credential_stuffing` como principal
(aislado); `slow_scan` como principal (aislado); ambos disparan, gana
el mayor score; el empate exacto ya descrito; `EntityID` correcto para
IP, sesión y grupo de red; toda `Decision` resultante verificada
contra `decision.Validate()`; concurrencia con `go test -race`.
`cmd/engine/main_test.go`: `buildServer()` extraído de `main()` (mismo
patrón que `cmd/eval/main.go`, tarea 0.8, con `run()`) para poder
probarlo con `httptest` — confirma que un evento normal da `ALLOW` y
que un patrón real de escaneo lento (50 rutas sensibles distintas,
todas 404) sobre el `*httpapi.Server` real termina en `CHALLENGE` o
`BLOCK`, con `attack_vector="slow_scan"`, usando la configuración real
de `cmd/engine` (no una de test); y que una `Policy` inválida hace
fallar `buildServer`.

**Verificación manual real con `curl`**, además de los tests
automatizados, contra `cmd/engine` corriendo de verdad
(`--challenge-threshold 0.5 --block-threshold 0.8`): un evento normal
dio `ALLOW` (`confidence_score:0`, `attack_vector:"unknown"`); 50
peticiones a rutas sensibles distintas, todas 404, sin Referer, desde
la misma IP, terminaron en `BLOCK` real
(`confidence_score:0.929`, `attack_vector:"slow_scan"`, con las seis
señales completas en `contributing_signals` y una `explanation`
determinista).

## 2026-09-25 — Detector estadístico de anomalías online: `internal/anomaly` (tarea 1.6)

**Qué es y qué NO es.** El tercer detector real, y el que satisface el
requisito del challenge de incluir "un modelo de detección de
anomalías estadístico o de ML". Es genuinamente estadístico, no otro
grupo de reglas disfrazado: media/varianza calculadas online con el
algoritmo de Welford, z-scores unilaterales, y un único umbral sobre
un score COMBINADO — a diferencia de `credstuffing`/`slowscan`, que
exigen varias señales crudas cruzando SUS PROPIOS umbrales a la vez.
Justifica de forma técnicamente correcta la frase: *"The engine
includes an online statistical anomaly detection model based on
running mean/variance and standardized deviations (z-scores)."* Sin
Isolation Forest, sin One-Class SVM, sin autoencoders, sin
dependencias Python — se descartaron explícitamente por agregar
complejidad real sin necesidad concreta para este prototipo.

**Modelo:** Welford (media, M2, varianza = M2/(n-1)) + z-score
unilateral (`z = max(0, (x-mean)/stddev)`, apropiado porque las cinco
features elegidas son todas "más alto = más sospechoso" en este
dominio).

**Features — todas ratios derivados de `profile.Metrics`, nunca
conteos crudos:** `NotFoundRatio`, `FailedAuthRatio`,
`PathDiversityRatio` (`len(PathCounts)/Total`), `WithoutRefererRatio`,
`AccountDiversityRatio` (`DistinctAccounts/Total` — señal distinta de
la correlación entre IPs que ya cubre `credstuffing`: acá mide cuántas
cuentas distintas probó **una sola entidad** por su cuenta).
Excluidas, con motivo: `Total` crudo (ver limitación 2 más abajo),
`WithReferer` (complemento exacto de `WithoutRefererRatio`, no suma
información), `DistinctSessions` (solo tiene sentido claro por IP, no
por sesión, complejidad no justificada).

**Dos limitaciones documentadas explícitamente, según lo pedido —
en el código (`internal/anomaly/detector.go`, docstring de `baseline`)
y acá:**

1. El baseline global mezcla poblaciones con formas de tráfico
   naturalmente distintas (un cliente de API y un navegador humano no
   son "iguales" solo porque ninguno es sospechoso), y una sola muestra
   por evento evaluado significa que una entidad muy activa aporta
   muchas muestras correlacionadas entre sí, pudiendo sesgar el
   baseline hacia su propia forma de tráfico.
2. Al excluir el volumen crudo (`Total`) de las features, este
   detector se enfoca en anomalías de la FORMA/proporciones del
   comportamiento — no pretende detectar por sí solo un incremento
   puramente volumétrico; eso ya es responsabilidad de
   `credstuffing`/`slowscan`.

**Población: global, no por IP/sesión — analizado y justificado.**
Un modelo por entidad nunca calentaría con el propio patrón de
credential stuffing distribuido de este proyecto (1-3 requests por
IP en total, tarea 0.5) — sería ciego exactamente al ataque que el
challenge pide detectar. Un baseline global, alimentado por el
snapshot de features de cada entidad evaluada, resuelve esto: una IP
nueva, con una sola observación, ya se puede puntuar contra "cómo se
ve normalmente un perfil", sin esperar su propia historia. IP y
sesión comparten el mismo baseline — un `NotFoundRatio` significa lo
mismo sin importar el tipo de entidad que lo produjo.

**Reutiliza `internal/profile.Store`, con un `*Store` privado** —
mismo criterio, mismo costo de memoria aceptado, que
`internal/slowscan` (tarea 1.4): el mismo evento queda retenido dos
(ahora tres) veces, una por cada detector, acotado por la ventana de
cada uno — trivial a esta escala, evita compartir un `Store` entre
detectores con necesidades de ventana potencialmente distintas. El
baseline de Welford en sí (un puñado de escalares) nunca crece con la
cantidad de entidades — a diferencia de `profile.Store`, no necesita
`Sweep` propio.

**Warm-up y orden score-antes-actualizar (tu preferencia explícita),
resuelto como una excepción documentada al patrón del proyecto.**
`n < MinSamples` → `Evaluate` siempre `Finding{}`, sin importar el
valor. `Observe(e)` en este detector **solo** alimenta el
`profile.Store` privado; el baseline de Welford se actualiza **dentro
de `Evaluate`**, después de puntuar contra una foto tomada al
principio (antes de que nada la modifique) — así el propio punto
anómalo nunca reduce artificialmente su propio z-score por haberse
promediado a sí mismo antes de calcularlo. Es una excepción
documentada al patrón "`Observe` muta, `Evaluate` solo lee" que sí
siguen `credstuffing`/`slowscan` — el contrato público (`Observe`
y después `Evaluate`) no cambia, el detalle es interno.

**Varianza cero → z=0, nunca NaN/Inf.** No se puede afirmar "cuántos
desvíos estándar" de algo que todavía no tiene desvío — se trata esa
feature como no informativa esta ronda, la opción conservadora.

**Anti-contaminación del baseline (baseline poisoning), analizado y
resuelto con la opción mínima.** Después del warm-up, una muestra
`Triggered=true` **no** se agrega al baseline — solo lo "normal"
actualiza la media/varianza. Durante el warm-up, toda muestra se
agrega sin excepción (no hay juicio de "anómalo" todavía, y excluir
desde el arranque podría dejar el baseline sin calentar nunca si el
tráfico inicial ya es mayormente ataque) — limitación conocida,
documentada, no resuelta acá (es un límite de cualquier baseline
aprendido sin supervisión).

**Combinación de z-scores en `RiskScore`, sin sumar z crudos.** Cada
`z_i` se normaliza a `[0,1)` con la misma familia de heurística
asintótica ya usada en `baseline`/`credstuffing`/`slowscan`, adaptada
a un z-score: `component = z/(z+ZSaturation)`. Los componentes se
combinan en un promedio ponderado (`Weights`, normalizado por su
suma). `Triggered` es un único umbral sobre ese score COMBINADO
(`TriggerThreshold`), no un gate conjuntivo de señales — la diferencia
de fondo con los otros dos detectores, ya explicada arriba.
`RiskScore = ScoreFloor + (1-ScoreFloor)*combined`, mismo mecanismo de
piso que 1.3/1.4, acá más una defensa adicional que la única barrera
(`TriggerThreshold > 0` ya garantiza `RiskScore > 0` en el borde
exacto).

**`AttackVector = unknown`, siempre — verificado contra el código
real, no solo argumentado.** `internal/eval/vector.go`
(`EvaluateVectorAttribution`, tarea 0.7) ya excluye
`decision.AttackVectorUnknown` del balde "Incorrecto" y lo cuenta
aparte como "Desconocido" — la semántica honesta que corresponde.
Inventar un vector nuevo (`"anomaly"`) rompería esto: como el ground
truth del evaluador solo conoce `legit`/`credential_stuffing`/
`slow_scan`, cualquier decisión con un vector nuevo caería siempre en
"Incorrecto" en esa comparación, penalizando injustamente a un
detector que está siendo honesto sobre sus límites. `unknown` no es
una limitación de este diseño, es la respuesta técnicamente correcta
dado cómo ya funciona el evaluador.

**`BehavioralDecider` generalizado a N detectores — interfaz privada
mínima, justificada recién ahora.** Con dos detectores (tarea 1.5),
comparar a mano alcanzaba. Con el tercero, `selectPrincipal` ya no
podía extenderse sin reescribirse — la misma "regla de tres" que ya
decidió cuándo extraer el patrón de ventana con watermark en este
proyecto. `internal/engine` agrega una interfaz `detector` privada
(`Observe`/`Evaluate`/`Sweep`), definida donde se consume — los tres
detectores ya la cumplen tal cual, sin tocarles ninguna firma. El
constructor `NewBehavioralDecider` sigue recibiendo los tres
detectores como parámetros explícitos y tipados (no una lista
genérica): el sitio de construcción en `cmd/engine` queda legible.
Prioridad de desempate fija: `credential_stuffing(0) > slow_scan(1) >
statistical_anomaly(2)` — el más específico gana un empate exacto; el
genérico es el último recurso. `explanationFor` se generalizó para
mencionar a todos los detectores secundarios que dispararon, no solo
"el otro".

**`cmd/engine`: `TriggerThreshold` deliberadamente bajo (0.15).** Con
las cinco features pesadas por igual, una desviación clara en una
sola de ellas nunca puede empujar el score combinado mucho más allá
de ~0.2 (las otras cuatro, cerca de su media, aportan ~0 al
promedio) — un `TriggerThreshold` alto haría que este detector nunca
dispare en la práctica. Mismo fenómeno encontrado y corregido durante
el desarrollo de los tests (ver más abajo).

**Tests.** `internal/anomaly/detector_test.go` (19 tests): validación
de configuración; media/varianza de Welford calculadas a mano
(secuencia `[1,2,3,4,5]`, mean=3, varianza=2.5); z-score calculado a
mano contra un `baselineSnapshot` armado directamente (mismo test
prueba a la vez que se puntúa contra el baseline PREVIO, no uno que
ya incluya la observación, porque el snapshot se arma antes de llamar
`evaluateFeatures` y nunca se modifica); varianza cero sin NaN/Inf;
`RiskScore` siempre en `[0,1)` sobre un barrido de magnitudes; warm-up
nunca dispara, sin importar el valor; tráfico estable no dispara;
desviación clara dispara; anomalía por `NotFoundRatio` y por
`FailedAuthRatio` por separado; entidad nueva puntuada contra un
baseline ya calentado por otras entidades; test explícito de
anti-contaminación (la misma muestra extrema enviada dos veces desde
entidades distintas da el mismo `RiskScore`, probando que la primera
nunca se filtró al baseline); `EntityID` correcto para IP y sesión;
concurrencia con `go test -race`. `internal/engine/behavioral_test.go`
(2 tests nuevos, más los 15 de la tarea 1.5 verificados sin cambios de
comportamiento gracias al `inertAnomalyConfig` de warm-up
deliberadamente inalcanzable): el `Finding` del detector estadístico
puede ser el principal cuando tiene mayor score; otro detector
(`slow_scan`) sigue siendo principal cuando su score es mayor aunque
el estadístico también dispare.

**Bug de test encontrado y corregido durante el desarrollo (no del
código de producción):** el primer intento de test de "desviación
clara dispara" usaba `TriggerThreshold=0.5`, y fallaba — no por un
error del detector, sino porque, con cinco features pesadas por igual
y una desviación en una sola de ellas, el score combinado
estructuralmente no puede superar ~0.2 (4 de 5 componentes quedan en
~0 si esa única feature es la que se disparó). Se bajó
`TriggerThreshold` a `0.1` en los tests (y a `0.15` en `cmd/engine`,
con margen), documentado como un valor de prueba, nunca calibrado
contra la semilla 42.

**Verificación manual real con `curl`**, además de los tests
automatizados: se calentó el baseline con 60 requests normales (10%
de 404, seis IPs distintas), y una entidad nueva mandó 20 requests a
la MISMA ruta (para no cruzar el gate de `slow_scan`, que exige
diversidad de rutas) con 90% de 404 — el motor real respondió
`CHALLENGE` con `attack_vector:"unknown"` y `not_found_ratio_z:29.4`,
confirmando que el detector estadístico, y no los otros dos, fue quien
disparó.
