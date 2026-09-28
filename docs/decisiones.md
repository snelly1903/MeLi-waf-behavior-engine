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

## 2026-09-26 — Enriquecimiento real de IP/ASN: `internal/asn` (tarea 1.7)

**Qué es y qué NO es.** Reemplaza el placeholder
`credstuffing.UnavailableNetworkResolver` por un `NetworkResolver`
real cuando se pide explícitamente — satisface el requisito del
challenge de enriquecer IPs con al menos una fuente pública/gratuita.
`internal/credstuffing` **no cambió ni una línea**: la interfaz
`NetworkResolver` (`Resolve(ip netip.Addr) (string, bool)`) ya existía
desde la tarea 1.3, y `asn.Resolver` la satisface por tipado
estructural de Go — `internal/asn` no importa `internal/credstuffing`
para nada, el detector nunca sabe qué proveedor hay detrás.

**Fuente: RIPEstat (RIPE NCC), `network-info`.** Gratuita, sin API
key — nada que hardcodear como secreto. Es una fuente apropiada para
este challenge/prototipo (RIPE NCC es uno de los cinco *Regional
Internet Registries* reales, no un scraper de terceros), pero **no se
presenta como el proveedor definitivo de un despliegue de
producción**: sus términos de uso actuales
(https://www.ripe.net/support/legal/terms/) restringen determinados
usos comerciales sin permiso explícito. Se agregó el parámetro
`sourceapp` (configurable, fijo por defecto al nombre del proyecto)
en cada consulta, siguiendo la propia guía de uso de RIPEstat, para
que un uso regular/automatizado quede identificable, no anónimo.

**Ajuste 1 — política conservadora ante múltiples ASN, sin elegir
arbitrariamente.** `network-info` puede devolver más de un ASN para
una IP (multi-homing). En vez de tomar el primero (inventaría una
correlación de grupo sin garantía), la regla es:

```
0 ASN        → ("", false)
exactamente 1 → ("asn:<número>", true)
más de 1      → ("", false)
```

Probado explícitamente en `TestResolve_MultipleASNs_ReturnsUnresolved`.

**Ajuste 2 — el timeout acota TODO `Resolve`, incluida la espera de
capacidad.** `Resolve` arma un único `context.WithTimeout` al
principio, y lo usa TANTO para esperar un cupo del semáforo de
concurrencia COMO para la llamada HTTP en sí
(`http.NewRequestWithContext`). Si el plazo se consume esperando
capacidad, devuelve `("", false)` sin haber llegado a consultar al
proveedor — nunca una espera sin límite antes del timeout configurado.
Probado en
`TestResolve_TimeoutConsumedWaitingForCapacity_NeverCallsProvider`
(ocupa el único cupo directamente sobre el campo interno del
semáforo, desde el mismo paquete, para que el test sea determinista y
no dependa de una carrera de tiempos entre dos timeouts — el primer
intento de este test SÍ tenía esa carrera y falló intermitentemente;
se corrigió antes de dejarlo).

**Documentado explícitamente: el lookup remoto síncrono es aceptable
para el prototipo, no sería el diseño de producción.** `Resolve` se
llama de forma síncrona dentro de `credstuffing.Detector.Observe`, en
el camino de cada request de `POST /v1/events`. Para este prototipo,
el timeout corto + el caché agresivo (ver más abajo) alcanzan. Para
tráfico masivo con muchas IPs nunca vistas, el diseño correcto sería
un enriquecimiento asíncrono/diferido que no bloquee la decisión
inicial — documentado como limitación conocida, no resuelta acá.

**Caché positivo y negativo, con TTL — mismo patrón `Sweep` que el
resto del proyecto.** Un mapa `IP → {grupo, ok, vencimiento}`
protegido por mutex; TTL largo para aciertos (`SuccessTTL`, un ASN
real cambia rara vez) y corto para fallos (`FailureTTL`, caché
negativo: no reintenta en cada request contra un proveedor caído,
pero sí reintenta pronto cuando vuelva). `Resolver.Sweep(now)` limpia
entradas vencidas — mismo patrón exacto que
`profile.Store`/`credstuffing.Detector`/`anomaly.Detector` (tareas
1.2/1.3/1.6), no conectado todavía a ningún scheduler, mismo criterio
ya documentado repetidamente.

**Límite de concurrencia propio.** Un semáforo (`chan struct{}`)
acota cuántas consultas HTTP puede haber en vuelo a la vez —
protección hacia el servicio público gratuito y contra una ráfaga de
IPs nunca vistas. **Sin deduplicación de ráfagas** (tipo
`singleflight`): bajo una ráfaga de la misma IP nunca vista podrían
salir 2-3 llamadas redundantes antes de que la primera cachee —
limitación aceptada y documentada, no una dependencia externa nueva
para un caso de baja probabilidad a esta escala.

**Reutiliza `event.Clock`, no otra interfaz de reloj más.** El TTL
del caché usa `event.Clock`/`event.SystemClock`/`event.ManualClock`
(tarea 0.2) — mismo criterio de no duplicar abstracciones ya
disponibles en el proyecto.

**Advertencia importante, verificada, no solo mencionada: RFC 5737 no
se puede enriquecer de verdad.** `internal/datagen` usa
deliberadamente rangos de documentación (`192.0.2.0/24`, etc. —
decisión de la tarea 0.4). Ningún proveedor real de ASN tiene datos
para esos rangos — contra nuestros propios datasets sintéticos, el
resolver real se comporta exactamente igual que
`UnavailableNetworkResolver` (siempre `ok=false`). No es un bug: es
la consecuencia correcta de una decisión de diseño ya tomada en la
Fase 0. La demostración manual (ver más abajo) usa IPs públicas
reales, no el dataset sintético, precisamente por esto.

**`cmd/engine`: `--asn-provider`, default seguro.** `"none"`
(default: `credstuffing.UnavailableNetworkResolver{}`, nunca hace
tráfico de salida a menos que se pida explícitamente — importante en
un contexto de seguridad y para entornos restringidos/offline) o
`"ripestat"` (`internal/asn.Resolver` real). Más `--asn-timeout` y
`--asn-cache-ttl`. Ningún secreto que configurar — RIPEstat no los
necesita.

**Tests.** `internal/asn/resolver_test.go` (17 tests, todos contra un
`httptest.Server` fake — ninguno depende de Internet real): validación
de configuración; parseo exitoso (con y sin el prefijo `"AS"`); el
caso multi-ASN pedido explícitamente; cero ASN; JSON malformado;
`status` HTTP distinto de 200; `status` de RIPEstat distinto de
`"ok"`; timeout con el proveedor real colgado (`elapsed` acotado
cerca del timeout configurado); timeout consumido esperando capacidad
sin llegar a llamar al proveedor; caché positivo evita una segunda
llamada; TTL positivo vence y vuelve a consultar; TTL negativo (más
corto) vence y reintenta; `Sweep` elimina solo lo vencido; límite de
concurrencia nunca superado (verificado contando conexiones
simultáneas reales al fake server); concurrencia general con
`go test -race`. `cmd/engine/main_test.go`: construcción del resolver
para cada valor de `--asn-provider` (incluido uno desconocido → error)
— sin llamadas de red, ya que construir un `asn.Resolver` no consulta
a nadie por sí solo.

**Verificación manual real, ejecutada con IPs públicas reales**
(requiere acceso real a Internet, a diferencia de todo lo demás en
este proyecto): se corrió `cmd/engine --asn-provider=ripestat` y se
armó una campaña de credential stuffing con 30 IPs públicas reales
dentro de `8.8.8.0/24` (Google, AS15169 — confirmado antes contra
RIPEstat en vivo, sin ninguna ambigüedad de multi-ASN), 15 cuentas
distintas, 84% de fallos. La `Decision` final:

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

correlación real de 30 IPs distintas de Internet en un mismo grupo de
ASN, de punta a punta.

**Hallazgo real durante esta verificación, documentado porque es
genuinamente instructivo:** el primer intento de la demo, con
exactamente 20 IPs (el mínimo configurado) y sin ninguna pausa entre
requests, **no disparó** — no por un bug, sino porque, bajo una
ráfaga rápida de 20 consultas distintas y casi simultáneas a un
servicio público gratuito, RIPEstat ocasionalmente tardó o falló para
alguna IP puntual (confirmado depurando paso a paso: `distinctIPs`
quedó en 19, no en 20, en esa corrida). El detector se comportó
exactamente como está diseñado: excluyó esa IP no resuelta de la
correlación (tarea 1.3) en vez de arriesgar un grupo incompleto — el
gate correctamente no disparó con evidencia insuficiente. La solución
no fue "arreglar un bug": fue dar margen real (30 IPs en vez de 20, un
pequeño `time.sleep(150ms)` entre requests) para absorber la
variabilidad inherente de depender de un servicio de terceros en el
camino síncrono de cada request — exactamente la limitación ya
documentada arriba ("el lookup remoto síncrono es aceptable para el
prototipo, no sería el diseño de producción"), ahora observada en la
práctica, no solo teorizada.

## 2026-09-26 — Observabilidad con OpenTelemetry + Grafana (tarea 1.8)

**Objetivo.** Cumplir el requisito de observabilidad del challenge con
una solución pequeña, local, reproducible y fácil de explicar: métricas
reales del motor (no decorativas), visibles en un dashboard de Grafana
provisionado automáticamente, sin exigirle Docker/Internet a ningún
test unitario.

### Arquitectura

```
cmd/engine (Go)  --OTLP/gRPC-->  OpenTelemetry Collector  --scrape-->  Prometheus  --query-->  Grafana
```

Se evaluó la alternativa más simple — el exportador Prometheus del
propio SDK de OTel, exponiendo `/metrics` directamente desde
`cmd/engine`, sin Collector — y se descartó: acoplaría el proceso Go al
formato de exposición de Prometheus específicamente, mientras que con
OTLP el proceso Go nunca sabe qué backend hay detrás (mañana se cambia
Prometheus por otra cosa tocando solo el Collector). El costo extra —
un contenedor y un YAML — es chico frente a lo que se gana.

**Qué corre en Docker Compose vs. en el proceso Go.** Los tres
contenedores (`otel-collector`, `prometheus`, `grafana`) corren en
`docker-compose.yml`. `cmd/engine` sigue corriendo local
(`go run ./cmd/engine`), apuntando su exportador OTLP a
`localhost:4317` — evita escribir un `Dockerfile` para el motor y
mantiene el ciclo de desarrollo tan simple como en las tareas
anteriores.

**Versiones de imagen fijas, nunca `latest`** (verificadas contra el
registry antes de fijarlas): `otel/opentelemetry-collector-contrib:0.113.0`,
`prom/prometheus:v2.54.1`, `grafana/grafana:11.2.0`.

### Paquetes de Go y dónde vive Init/Shutdown

`go.opentelemetry.io/otel`, `otel/sdk`, `otel/sdk/metric`,
`otel/exporters/otlp/otlpmetric/otlpmetricgrpc`, y
`go.opentelemetry.io/contrib/.../otelhttp`. Fijar estas versiones
(`go get ... @latest`, después congeladas en `go.mod`/`go.sum`) subió
automáticamente el `go` directive del módulo de 1.23.1 a 1.25.0 — las
versiones actuales del SDK de OTel ya piden un Go más nuevo; Go
descargó su propio toolchain 1.25.0 sin ninguna intervención manual y
el proyecto sigue compilando y pasando todos los tests igual. Se deja
documentado como un efecto observado, no una decisión buscada.

Un paquete nuevo, `internal/telemetry`, es el ÚNICO del proyecto que
importa el SDK de OpenTelemetry para las métricas de dominio.
`internal/telemetry.Init(ctx, cfg)` se llama una sola vez, al principio
de `cmd/engine/main()`; el `shutdown` que devuelve se llama una sola
vez, al final, con un contexto nuevo y acotado (ver "Apagado
ordenado" más abajo). Ni `internal/engine`, ni `internal/asn`, ni
`internal/httpapi` importan OpenTelemetry — cada uno define su propia
interfaz mínima de consumo (`engine.FindingsRecorder`,
`asn.MetricsRecorder`, `httpapi.DecisionRecorder`), que
`internal/telemetry` implementa desde afuera por tipado estructural —
mismo criterio que `internal/asn.Resolver` satisface
`credstuffing.NetworkResolver` desde la tarea 1.3.

### Métricas — verificadas de verdad, no asumidas

El ajuste 1 pedía explícitamente no asumir el nombre real que
`otelhttp` exporta y verificarlo durante la integración. Se hizo: se
corrió el stack completo, se generó tráfico real, y se leyó
directamente `curl http://localhost:8889/metrics` (el exportador
Prometheus del Collector). Nombres reales confirmados:

| Métrica (nombre real en Prometheus) | Tipo | Unidad | Labels | Dónde se registra | Pregunta que responde |
|---|---|---|---|---|---|
| `http_server_request_duration_seconds` | Histogram | s | `http_route` (2 valores), `http_request_method`, `http_response_status_code` | `otelhttp.NewHandler` envolviendo el mux en `cmd/engine/main.go` | Volumen y latencia end-to-end de cada endpoint |
| `waf_decisions_total` | Counter | 1 | `action` (3), `attack_vector` (3) | `httpapi.handleEvents`, justo después de `Decide` | Decisiones por action y por attack_vector |
| `waf_detector_findings_total` | Counter | 1 | `detector` (3) | `engine.BehavioralDecider.Decide`, por cada detector con `Finding.Triggered` | Qué detector dispara, incluso el que pierde el desempate |
| `waf_asn_cache_total` | Counter | 1 | `result` (hit/miss) | `asn.Resolver.Resolve`, según `cacheGet` | Efectividad del caché de ASN |
| `waf_asn_resolve_total` | Counter | 1 | `result` (success/failure/capacity_timeout) | `asn.Resolver.Resolve`, tras `fetch` o tras el timeout de capacidad | ¿RIPEstat responde? ¿Cuánto pesa la contención local? |
| `waf_asn_provider_duration_seconds` | Histogram | s | `result` (success/failure) | `asn.Resolver.Resolve`, alrededor de `fetch` | Cuánto tarda realmente la llamada HTTP al proveedor |

**Ajuste 2 (renombre) aplicado**: la métrica de duración del ASN mide
específicamente la llamada HTTP a `fetch`, nunca `Resolve()` completo
(que también incluye la espera de capacidad y el caché) — por eso se
llama `waf.asn.provider.duration` (→ `waf_asn_provider_duration_seconds`
en Prometheus), no `waf.asn.resolve.duration`. Verificado en la demo:
`waf_asn_resolve_total{result="success"}=30` junto con
`waf_asn_provider_duration_seconds_count{result="success"}=30` —
exactamente una medición de duración por cada resolución real, nunca
por los `capacity_timeout` (ahí nunca hubo ninguna llamada que medir).

**Decisión explícita de NO agregar** una métrica de latencia solo para
`engine.Decide`: `httpapi.handleEvents` hace decode→validate→Decide→encode,
y decode/validate/encode de un evento son microsegundos frente al
trabajo de los detectores — sería casi idéntica a la latencia HTTP de
`POST /v1/events` y solo agregaría una serie más para mantener sin
información nueva.

### Cardinalidad

Ningún label es `client_ip`, `request_id`, `entity_id`, `session_id`,
`login_user_hash`, ruta cruda ni un número de ASN individual. Todos los
labels son conjuntos fijos y chicos: `action` (3), `attack_vector` (3),
`detector` (3), `result` (2 o 3), `http_route` (2). Combinación máxima
observada: `waf_decisions_total` con 3×3=9 series.

### Dónde se instrumenta sin contaminar el dominio

`internal/credstuffing`, `internal/slowscan` e `internal/anomaly`:
**cero cambios**, ningún import de OpenTelemetry. `internal/httpapi`
agrega `DecisionRecorder` (interfaz mínima, nil-safe con un no-op por
defecto). `internal/engine` agrega `FindingsRecorder` a
`BehavioralDecider`, con la misma convención. `internal/asn` agrega
`MetricsRecorder` a `Resolver`. Las tres son implementadas desde
`internal/telemetry`, cableadas en `cmd/engine/main.go`.

**Ajuste 6 aplicado**: `waf.detector.findings` usa el nombre del
detector ya registrado explícitamente en `namedDetector.name`
("credential_stuffing", "slow_scan", "statistical_anomaly", fijado en
`NewBehavioralDecider` desde la tarea 1.6) — nunca se infiere con un
`type switch` sobre el detector concreto; de hecho no hizo falta
escribir ningún código nuevo para esto, el campo ya existía con el
nombre correcto.

### Fail-open: el ajuste central de esta tarea

`internal/telemetry.Init` nunca devuelve un estado que le impida a
`cmd/engine` arrancar. Tres casos, probados en
`internal/telemetry/telemetry_test.go`:

1. `--otel-endpoint` vacío (default) → no-op sin ningún intento de red
   (`TestInit_EmptyEndpoint_IsNoopWithoutDialing`).
2. `--otel-endpoint` configurado pero el Collector no responde dentro
   de `--otel-connect-timeout` → no-op, `usedNoop=true`, tiempo total
   acotado cerca del timeout — nunca un error que frene el arranque
   (`TestInit_CollectorUnreachable_FallsBackToNoop`, contra un puerto
   TCP real cerrado, sin mocks).
3. Collector alcanzable → `MeterProvider` real.

La verificación de "alcanzable o no" es síncrona y ocurre en `dial()`:
se arma un `*grpc.ClientConn` con `grpc.NewClient` (la forma moderna,
que nunca conecta por sí sola) y se espera explícitamente
`connectivity.Ready` con `conn.WaitForStateChange`, acotado por
`ConnectTimeout` — se evitó la vieja `grpc.WithBlock()` porque su
propia documentación dice que `NewClient` ya no la soporta.

`cmd/engine/main.go` logea la advertencia de fallback (`usedNoop &&
endpoint != ""`) — `internal/telemetry` nunca escribe logs por su
cuenta, para quedar testeable sin capturar stdout.

### `--otel-insecure` (ajuste 4)

La conexión gRPC local de esta tarea usa `insecure.NewCredentials()`
explícitamente vía `--otel-insecure=true` (default). Documentado sin
ambigüedad: esto es válido únicamente para un Collector local en la
misma máquina/red de confianza — un endpoint remoto de producción
debería correr con `--otel-insecure=false`, que activa
`credentials.NewTLS` con la configuración estándar de verificación
contra las CA del sistema.

### `otelhttp` con el `MeterProvider` explícito (ajuste 5)

`cmd/engine/main.go` pasa `otelhttp.WithMeterProvider(recorders.Provider)`
en vez de depender del proveedor global — se confirmó en la versión
usada (`otelhttp` v0.71.0) que la opción existe exactamente para esto
("If none is specified, the global provider is used"), así que no
hubo ninguna razón técnica para no pasarlo explícito. Es la única
excepción, documentada, a preferir la convención propia del proyecto
(inyección explícita) sobre la convención estándar de OTel (proveedor
global): las métricas de dominio (`waf.decisions`, `waf.detector.findings`,
`waf.asn.*`) sí siguen la inyección explícita de siempre.

### Apagado ordenado (ajuste 8)

`cmd/engine/main.go` no tenía manejo de señales — `main()` ahora usa
`signal.NotifyContext(context.Background(), os.Interrupt,
syscall.SIGTERM)`. Al recibir la señal: `httpServer.Shutdown` con un
contexto acotado a 5s (deja de aceptar conexiones nuevas, drena las en
curso), y — recién después de que `ListenAndServe` retorna — un
**segundo** contexto nuevo y acotado a 5s, exclusivamente para
`telemetry` `Shutdown` (que hace flush del `MeterProvider` y cierra la
conexión gRPC). Nunca se reutiliza el `ctx` de la señal, que para ese
momento ya está cancelado y no le daría ningún margen real al flush
final. Verificado manualmente (no con un test automatizado — es
comportamiento de `main`, no de un paquete): se envió `SIGTERM` a un
binario real corriendo con `--otel-endpoint` configurado, y el log
mostró "señal de apagado recibida, cerrando ordenadamente" seguido de
una terminación limpia, sin quedar colgado.

### Tests sin Docker/Prometheus/Grafana/Internet

Las interfaces mínimas se prueban con fakes en memoria
(`fakeFindingsRecorder` en `internal/engine`, `fakeMetricsRecorder` en
`internal/asn`, `fakeDecisionRecorder` en `internal/httpapi`) — mismo
estilo que `fakeResolver` desde la tarea 1.3. El adaptador real de
`internal/telemetry` se prueba con `sdkmetric.NewManualReader()` (sin
ningún exportador de red): se registra una medición y se lee
sincrónicamente el resultado ya agregado, la forma oficialmente
soportada por el SDK de OTel para testear instrumentación sin
Collector. `TestEngineRecorder_...`, `TestHTTPRecorder_...` y
`TestASNRecorder_...` verifican, contra el `ManualReader`, el nombre
exacto de cada instrumento y sus atributos — el mismo nombre que
después se confirmó en la demo real.

### Docker Compose y provisioning de Grafana

`otel/collector-config.yaml` (receiver `otlp` gRPC, processor
`batch`, exporter `prometheus` en `:8889`); `prometheus/prometheus.yml`
(un único scrape job hacia `otel-collector:8889`);
`grafana/provisioning/datasources/datasource.yml` (datasource
Prometheus con `uid: prometheus` fijo, para que el JSON del dashboard
pueda referenciarlo sin variables de plantilla);
`grafana/provisioning/dashboards/dashboard-provider.yml` +
`grafana/dashboards/waf-engine.json` (8 paneles). Acceso anónimo de
solo lectura habilitado en Grafana (`GF_AUTH_ANONYMOUS_ENABLED=true`,
rol Viewer) — únicamente para que este demo local no le exija login al
evaluador; el panel de administración sigue pidiendo `admin/admin`.
Nunca se expondría así fuera de una demo local.

### Verificación manual real, de punta a punta

Se corrió `docker compose up -d`, se levantó `cmd/engine` local
apuntando a `localhost:4317`, y se generó tráfico real de tres formas:

1. **ALLOW**: 5 requests normales a `/` → `waf_decisions_total{action="ALLOW",attack_vector="unknown"}`.
2. **slow_scan**: 50 requests a rutas distintas, todas 404, sobre una
   misma IP → `action=BLOCK`, `attack_vector=slow_scan`,
   `waf_detector_findings_total{detector="slow_scan"}=36`.
3. **statistical_anomaly**: un baseline de 200 IPs de un solo request
   cada una (≈1% sin `Referer`, variabilidad real, no un valor
   idéntico repetido) seguido de una entidad nueva sosteniendo
   `Referer` ausente en 10 requests → `Finding.Triggered=true` con
   `without_referer_ratio_z≈9.87` (`risk score` 0.33, por debajo del
   `challenge threshold` 0.50, así que `action` siguió en `ALLOW` pero
   con la evidencia completa preservada — mismo diseño ya documentado
   en la tarea 1.5) → `waf_detector_findings_total{detector="statistical_anomaly"}=10`.
4. (Opcional, también verificado) **credential_stuffing con RIPEstat
   real**: 30 IPs públicas de Google (`8.8.8.1`-`8.8.8.30`, AS15169),
   15 cuentas, 80% de fallos → `entity_id=network:asn:15169`,
   `waf_asn_cache_total{result="hit"}=30` y `{result="miss"}=30` (cada
   IP se resuelve dos veces por evento — una vez desde
   `credstuffing.Observe`, otra desde `Evaluate`; la primera es
   siempre miss, la segunda siempre hit gracias al caché — ningún
   comportamiento nuevo, solo confirma cómo ya funcionaba
   `credstuffing.Detector` desde la tarea 1.3),
   `waf_asn_resolve_total{result="success"}=30`,
   `waf_asn_provider_duration_seconds_sum{result="success"}≈10.26s`
   sobre 30 llamadas reales.

Los ocho paneles se confirmaron cargados vía la propia API de Grafana
(`GET /api/dashboards/uid/waf-behavior-engine` → 8 panels) y una query
real ejecutada a través del proxy de Grafana hacia Prometheus devolvió
datos reales — no solo "la config parece bien", sino "Grafana
efectivamente sirve estos números".

**Hallazgo real durante esta verificación, documentado porque es
instructivo (mismo espíritu que el de la tarea 1.7):** el primer
intento de forzar `statistical_anomaly` con tráfico real fue mucho más
difícil de lo esperado, y expuso dos límites genuinos del diseño de la
tarea 1.6, no solo teóricos:

1. Un baseline con **cero varianza real** (todas las muestras
   idénticas, ej. siempre con `Referer`) desactiva por completo el
   z-score de esa feature — `evaluateFeatures` trata explícitamente
   `stddev <= zEpsilon` como "sin información" (`z=0`), a propósito,
   para no dividir por (casi) cero y explotar. Es correcto y
   deseable, pero significa que un dataset sintético demasiado
   homogéneo nunca puede disparar este detector, sin importar cuán
   extrema sea la desviación — hace falta variabilidad real en el
   baseline primero.
2. Como el baseline es **global** (ya documentado como limitación
   desde la tarea 1.6) y las muestras que no disparan se siguen
   agregando al baseline, varios intentos fallidos consecutivos, sobre
   el mismo proceso corriendo, terminaron **contaminando su propio
   baseline** con las mismas muestras "anómalas" que no habían
   disparado — inflando la varianza aprendida y haciendo cada intento
   posterior más difícil, no más fácil. Reiniciar el proceso (baseline
   en memoria, se pierde al reiniciar — tarea 1.6) y hacer un único
   intento bien calculado fue lo que finalmente funcionó.

Ninguno de los dos es un bug: son la consecuencia directa, observada en
la práctica, de un diseño ya documentado (baseline global, z-score
protegido contra varianza cero). Se deja constancia acá porque es
exactamente el tipo de comportamiento que vale la pena poder explicar
en una entrevista.

### Criterios de cierre

`gofmt -l .` limpio; `go vet ./...` sin hallazgos; `go test -race ./...`
verde en todos los paquetes, incluido `internal/telemetry` (nuevo);
`docker compose config` válido; el stack arranca localmente (3
contenedores healthy); métricas reales (no inventadas) visibles en
Prometheus y en Grafana; dashboard funcional con 8 paneles, cargado
sin ningún paso manual del evaluador; esta sección de
`docs/decisiones.md` actualizada con el resultado real, no un plan.

No se hizo ningún `git add`/`git commit`. No se avanza a la tarea 1.9
sin aprobación explícita.

### Adenda — vulnerabilidades de dependencias detectadas post-implementación

El IDE (plugin Red Hat Dependency Analytics, que usa OSV/GitHub
Advisories) marcó `google.golang.org/grpc@v1.83.1` con una
vulnerabilidad HIGH. Se investigó con dos fuentes independientes antes
de tocar nada:

1. **`govulncheck`** (el escáner oficial de Go, que hace análisis de
   alcanzabilidad real contra el código propio) — no reportó ningún
   problema en `grpc` en absoluto, ni siquiera como "no alcanzable".
   En cambio encontró **31 vulnerabilidades reales de la librería
   estándar de Go**, todas ya arregladas en parches posteriores a
   `go1.25.0` — consecuencia directa de que `go get ... @latest`
   había fijado el `go` directive del módulo en exactamente `1.25.0`
   durante la implementación de esta tarea.
2. **Consulta directa a la API de OSV.dev** por la versión exacta
   `1.83.1`, para identificar la vulnerabilidad puntual del IDE:
   `GHSA-2v4p-qf9q-27wj` / `CVE-2026-84445` / `GO-2026-6443` — un panic
   de denegación de servicio en servidores gRPC configurados con
   `xds.NewGRPCServer()` (xDS), cuando un request llega sin los
   headers `:authority` ni `Host`. Este proyecto **nunca usa gRPC como
   servidor XDS** — `internal/telemetry` solo lo usa como *cliente*
   (`grpc.NewClient` para hablar con el Collector vía
   `otlpmetricgrpc`) — exactamente por eso `govulncheck` no lo marcó:
   el código vulnerable jamás es alcanzable desde este binario. El
   aviso del IDE es correcto sobre la versión de la librería, pero no
   distingue si el código vulnerable específico se usa o no.

**Corrección aplicada, aunque el código no fuera alcanzable** (es un
bump de parche, sin riesgo, y elimina el ruido de la alerta):
`google.golang.org/grpc` a `v1.83.2` (la versión donde se arregló
`GHSA-2v4p-qf9q-27wj`), y el `go` directive del módulo de `1.25.0` a
`1.25.14` (el último parche de la misma línea 1.25 — no un salto de
versión de lenguaje, solo la corrección de seguridad de la librería
estándar). Verificado: `govulncheck ./...` pasó de 31+ hallazgos a
`No vulnerabilities found`, y `gofmt -l .` / `go vet ./...` /
`go test -race ./...` siguen en verde.

## 2026-09-27 — Evaluation and Tuning: baseline offline (tarea 1.9, paso 1)

**Objetivo de la tarea completa.** Medir y calibrar el motor
conductual de forma reproducible, evitando overfitting: separar
calidad del detector (Finding → Triggered, risk scoring) de calidad
de la política (ALLOW/CHALLENGE/BLOCK), usando datasets de tuning y
de holdout final generados con semillas distintas. Este primer paso
implementa únicamente el baseline (configuración actual, sin ningún
cambio de threshold) y la infraestructura mínima para producirlo — el
resto del proceso (calibrar detectores, calibrar policy, holdout)
queda pendiente de aprobación explícita después de este Punto de
Control.

### Qué ya existía y se reutilizó tal cual

`internal/eval` ya tenía casi todo lo que pedía el PDF: matriz de
confusión, precision/recall/FPR/FNR con `Ratio{Defined bool}` (N/A
real, nunca un 0 disimulado), políticas `PolicyStrict`/`PolicyBroad`,
recall por vector de ataque (`ByAttackVectorRecall`), atribución de
vector. `internal/datagen` ya tenía semillas reproducibles
(`NewRNG`), generación con proporción configurable (0/10/30%) y
escritura de escenarios. `internal/baseline/io.go` ya tenía I/O
genérico de eventos/decisiones (nunca específico del rate-limiter de
la tarea 0.9) — se reutilizó directo. Nada de esto se duplicó.

### Lo nuevo (mínimo, aditivo)

- **F1**, agregado a `internal/eval.Metrics` — indefinido (N/A) si
  Precision o Recall lo son, o si ambas dan exactamente 0 (2·0·0/0).
- **`Policy.IsPositive`** (método exportado en `internal/eval`, antes
  privado) — para que `internal/tuning` pueda decidir "detectado"
  con la MISMA regla que ya usa `BuildConfusionMatrix`, sin
  duplicarla.
- **`internal/datagen.SimulatedASNResolver`** — resolver determinista
  offline (IP → ASN simulado, por prefijo `/24`, usando los mismos
  `IPPool` con los que se generó el tráfico) para credential
  stuffing. Nunca usa RIPEstat contra IPs sintéticas — no tendría
  sentido, y el propio `internal/asn.Resolver` ya documenta que RFC
  5737 nunca resuelve contra un proveedor real (tarea 1.7).
- **`internal/engine/defaults.go`** — `DefaultCredentialStuffingConfig`/`DefaultSlowScanConfig`/`DefaultAnomalyConfig`/`DefaultPolicy`,
  movidos (no copiados) desde `cmd/engine/main.go`. Ajuste 2 del
  plan aprobado: el "baseline" de esta evaluación tiene que ser
  EXACTAMENTE la configuración que sirve `cmd/engine`, nunca una
  copia a mano que pudiera desincronizarse — un refactor chico
  (mover literales, no lógica) resolvió esto de raíz, sin necesitar
  un test de "drift" como red de seguridad separada:
  `internal/tuning.BaselineCandidate()` llama a las mismas funciones
  que ahora llama `cmd/engine`, así que no hay dos copias que puedan
  desincronizarse — solo un test que confirma que
  `BaselineCandidate()` sigue llamándolas (`TestBaselineCandidate_MatchesEngineDefaults`).
- **`internal/tuning`** (paquete nuevo): `Candidate`/`Build` (arma un
  `BehavioralDecider` con estado fresco — profiles y baseline de
  anomaly vacíos por diseño, ninguna corrida contamina a la
  siguiente), `Replay` (corre el motor real sobre un escenario en
  memoria, sin HTTP), `ComputeDetectionDelay`/`CampaignDelay`
  (detection delay y "eventual campaign detection" — ver ajuste 1
  más abajo), `SummarizeDelay` (agregación por vector),
  `RunScenario` (une todo lo anterior), y `Row`/`WriteCSV`/`WriteJSON`/`RenderMarkdown`
  (exportación completa, ver ajuste 3).
- **`cmd/tune`**: por ahora, solo corre `BaselineCandidate` sobre los
  escenarios de tuning y escribe el reporte. El sweep de candidatos
  llega en el próximo paso.

### Ajuste 1 del plan: campaign key por vector, nunca uniforme

`ComputeDetectionDelay` agrupa eventos maliciosos en "campañas" con
una regla DISTINTA por vector, nunca la misma:

- `slow_scan` → una campaña por entidad que escanea (sesión si
  existe, si no la IP) — cada escáner es independiente, igual que lo
  ve `internal/slowscan.Detector`.
- `credential_stuffing` → una campaña por grupo de red (el mismo
  `SimulatedASNResolver` que usa el propio detector) — el detector
  correlaciona por ASN, nunca por IP individual, así que medir delay
  por IP habría sido conceptualmente incorrecto: todas las IPs
  atacantes de la misma campaña distribuida comparten una sola
  campaña. Verificado con un test dedicado
  (`TestComputeDetectionDelay_CredentialStuffing_GroupsByASNNotByIP`):
  dos IPs distintas del mismo grupo forman una sola campaña, y la
  detección de CUALQUIERA de las dos cuenta como la detección de la
  campaña completa.

### Ajuste 3 del plan: auditabilidad completa del sweep

Aunque este paso solo tiene un candidato ("baseline"), el formato de
exportación (`Row`, en `internal/tuning/report.go`) ya está diseñado
para la comparación completa: una fila por candidato×seed×ratio, con
TP/FP/TN/FN, precision/recall/FPR/FNR/F1 strict Y broad, recall por
vector, y detection delay (campañas, detectadas, tasa, requests/tiempo
medio) — nunca preagregado, para poder reconstruir después, a partir
de las filas crudas, por qué se habría elegido cada configuración.
`reports/tuning/baseline.{md,csv,json}` ya sigue este formato.

### Verificación

`gofmt -l .` limpio, `go vet ./...` sin hallazgos, `go test ./...` y
`go test -race ./...` verdes en todos los paquetes, incluido
`internal/tuning` (nuevo).

**Hallazgo real durante la implementación, no relacionado con esta
tarea en sí:** el primer intento de un test de reproducibilidad
bit-a-bit (`TestRunScenario_Reproducible_SameSeedSameResult`) falló —
no en `Action`/`AttackVector` ni en ninguna métrica, solo en
`ConfidenceScore`, con una diferencia de ~1e-16 (un ULP). Causa
raíz: `internal/slowscan` acumula entropía iterando
`profile.Metrics.PathCounts`, un `map[string]int]` — Go aleatoriza a
propósito el orden de iteración de un map entre corridas del
proceso, así que la SUMA en coma flotante de esos términos puede
diferir en el último bit entre dos corridas con la misma semilla,
aunque la lógica sea 100% determinista. Nunca cambia ninguna
decisión real (los umbrales de Policy están en 0.5/0.8, lejísimos de
un ULP) — se ajustó el test para comparar lo que realmente importa
(Action/AttackVector/EntityID, y las métricas derivadas de esos
campos, que sí son bit-a-bit idénticas) en vez de exigir un
`reflect.DeepEqual` sobre `ConfidenceScore`. No se tocó
`internal/slowscan` — está fuera del alcance de este paso.

### Resultados del baseline (config actual de `cmd/engine`, sin ningún cambio)

3 seeds (101/102/103) × 3 ratios (0/10/30%) = 9 corridas, ~1100-1750
eventos cada una. Reporte completo en `reports/tuning/baseline.{md,csv,json}`.

| Seed | Ratio | Strict TP/FP/FN/TN | Broad TP/FP/FN/TN | Recall CS | Recall SS | CS delay (campañas/detectadas/req.medio) | SS delay |
|---|---|---|---|---|---|---|---|
| 101 | 0% | 0/0/0/1183 | 0/**41**/0/1142 | N/A | N/A | — | — |
| 101 | 10% | 23/0/115/1183 | 121/30/17/1153 | 0.842 | 0.890 | 1/1/4.0 | 2/2/1.0 |
| 101 | 30% | 32/0/486/1183 | 228/23/290/1160 | 0.872 | **0.254** | 1/1/6.0 | 9/9/5.33 |
| 102 | 0% | 0/0/0/1134 | 0/**76**/0/1058 | N/A | N/A | — | — |
| 102 | 10% | 30/0/98/1134 | 114/65/14/1069 | 0.977 | 0.847 | 1/1/2.0 | 2/2/2.5 |
| 102 | 30% | **0**/0/487/1134 | 292/33/195/1101 | 0.961 | **0.436** | 1/1/6.0 | 9/8/6.38 |
| 103 | 0% | 0/0/0/1178 | 0/**47**/0/1131 | N/A | N/A | — | — |
| 103 | 10% | 11/0/137/1178 | 127/33/21/1145 | 0.957 | 0.812 | 1/1/3.0 | 2/2/8.0 |
| 103 | 30% | 1/0/571/1178 | 253/24/319/1154 | 0.948 | **0.225** | 1/1/6.0 | 9/6/21.33 |

### Errores concretos observados

**1) Falsos positivos en 0% malicious — solo bajo política amplia,
siempre atribuibles a `statistical_anomaly`.** `strict_fp=0` en los
tres seeds (BLOCK nunca dispara sobre tráfico 100% legítimo), pero
`broad_fp` va de 41 a 76 (FPR 3.5%–6.7%) — ningún request de 0%
malicious puede activar el gate conjuntivo de `credstuffing` ni de
`slowscan` (exigen un patrón de ataque real), así que estos 41–76
CHALLENGE por corrida son, por eliminación, `statistical_anomaly`
reaccionando a variación natural y legítima del tráfico (algún
cliente API, algún oficinista con un patrón de referer/rutas poco
común). Es el costo real que hay que sopesar contra cualquier mejora
de recall — exactamente el criterio de selección que pediste no
perder de vista.

**2) `strict_recall` (BLOCK) es casi inexistente y empeora al subir
la ratio maliciosa.** 0.167→0.062 (seed 101), 0.234→**0.000** (seed
102), 0.074→0.002 (seed 103) al pasar de 10% a 30%. `BlockThreshold=0.8`
parece estar calibrado muy por encima de los `RiskScore` que estos
dos detectores producen incluso ante un ataque claro (ya se había
visto en la demo manual de la tarea 1.7 que `credential_stuffing`
rara vez supera ~0.5) — BLOCK depende casi enteramente de los casos
más extremos de `slow_scan`, y esos son escasos y ruidosos entre
seeds (`strict_tp` en 30%: 32, 0, 1 — altísima varianza para la MISMA
ratio, solo cambiando la semilla).

**3) `recall_slow_scan` cae fuerte al subir la ratio (10%→30%),
mientras que `recall_credential_stuffing` se mantiene estable o
mejora.** slow_scan: 0.890→0.254 (101), 0.847→0.436 (102),
0.812→0.225 (103). credential_stuffing: 0.842→0.872 (101),
0.977→0.961 (102), 0.957→0.948 (103) — sin degradación. La causa,
visible directamente en el detection delay: a 30% hay 9 campañas de
scanner en vez de 2 (el generador reparte el mismo presupuesto de
tráfico malicioso entre más escáneres), así que cada campaña
individual es más chica — y como el gate de `slowscan` exige un
`MinRequests=15` (entre otras condiciones) ANTES de disparar, una
porción más grande de cada campaña más chica ocurre necesariamente
antes de cruzar ese piso. La detección "eventual" de la campaña se
mantiene alta (100% en seed 101, 88.9%/66.7% en 102/103) — el
detector casi siempre atrapa al escáner tarde o temprano — pero el
recall a NIVEL DE REQUEST, que es la métrica principal, cae
correctamente y sin disimularlo: `ss_mean_requests_to_detection` sube
de ~1–2.5 (10%) a 5.3–21.3 (30%), confirmando que la demora de
detección creció, no que el detector empeoró su lógica. Esto es
justo lo que pediste vigilar explícitamente ("no uses estas métricas
para ocultar false negatives iniciales") — y el propio diseño ya lo
expone en vez de esconderlo.

**4) `credential_stuffing` funciona de forma sólida y estable en este
baseline**: recall 84–98% en ambas ratios, exactamente 1 campaña por
escenario (confirma que el ajuste 1 agrupa por ASN, no por IP, como
se pidió), detectada siempre dentro de su ventana de 30 minutos
(`cs_mean_seconds_to_detection` entre 225 y 792 segundos). No parece
necesitar ningún cambio urgente — a diferencia de `slow_scan` y de
`statistical_anomaly`.

Ningún parámetro se tocó todavía. Se espera aprobación antes de
empezar cualquier calibración.

## 2026-09-27 — Pasada diagnóstica antes de calibrar (tarea 1.9, Punto de Control 2)

**Objetivo.** Antes de tocar ningún threshold, entender con evidencia
explícita (nunca por eliminación) qué parámetro concreto causa cada
error observado en el baseline. Reporte completo, reproducible:
`reports/tuning/diagnose.md` (`go run ./cmd/diagnose`).

### Infraestructura nueva (diagnóstico, aditiva, sin cambiar comportamiento)

- `anomaly.Detector.EvaluateDebug` — expone el score combinado y los
  z-scores de cada scope ANTES de compararlos con `TriggerThreshold`,
  algo que `Evaluate` descarta (`finding.Finding{}`) en el caso no
  disparado. Se extrajo `scoreFeatures` como núcleo compartido — cero
  cambio de comportamiento en `Evaluate`, confirmado con los tests ya
  existentes y tres nuevos (`TestEvaluateDebug_*`).
- `slowscan.Detector.EvaluateGateMetrics` — expone TotalRequests,
  DistinctPaths, NotFoundRatio, RouteEntropy y NovelPathRatio de
  cualquier scope, disparado o no. `evaluateMetrics` se refactorizó
  para llamar al mismo `gateMetricsFor` interno — una sola fórmula,
  no dos copias que pudieran desincronizarse. Sin cambio de
  comportamiento (mismos tests existentes en verde + 3 nuevos).
- `internal/tuning`: `RunDiagnostics` (corre tres detectores propios,
  en paralelo a la corrida real, capturando el Finding de CADA UNO
  por evento), `AnalyzeAnomalyFalsePositives`, `AnalyzeSlowScanCampaigns`,
  `AnalyzeRiskScoreDistributions`, `Summarize`/`PercentileSummary`
  (min/p50/p75/p90/p95/max, método nearest-rank). `cmd/diagnose` las
  corre sobre los mismos 9 escenarios de tuning que `cmd/tune`.

### 1. Falsos positivos de statistical_anomaly — confirmado explícitamente, no por eliminación

Los 164 FP (broad) de las corridas de 0% tienen **prueba estructural
explícita**: para cada uno se verificó que
`CredentialStuffing.Triggered=false` y `SlowScan.Triggered=false`, y
que existe una evaluación de anomaly con `Triggered=true` —
`PrincipalDetectorConfirmed=true` en el 100% de los 164 casos (0
excepciones).

**El corte matemático que sugeriste se confirma casi exacto con datos
reales**: el score combinado máximo entre los 3331 ALLOW es
**0.3749**; el mínimo entre los 164 CHALLENGE es **0.3758** — el
límite teórico (ScoreFloor=0.20, Challenge=0.50 → combined≈0.375) se
verifica en la práctica, casi al cuarto decimal.

**Consecuencia directa para elegir el parámetro relevante**:
`TriggerThreshold` (actual 0.15) está muy por debajo de ese ~0.375 —
cambiarlo dentro de {0.10, 0.15, 0.20} **no puede mover ni un solo
evento** de estos 164 de CHALLENGE a ALLOW (todos tienen combined
≥0.3758, muy por encima de cualquier valor del grid propuesto).
`ZSaturation` sí es relevante, pero de forma desigual: se recalculó a
mano el primer FP de la tabla (failed_auth_z=11.25,
path_diversity_z=1.96, without_referer_z=2.65,
account_diversity_z=11.25) — con ZSaturation=3 el combined baja de
0.5527 a 0.4884 (sigue disparando), con ZSaturation=1 SUBE a 0.6448
(empeora). Para los casos con z extremos (hasta 74 en
failed_auth_z/account_diversity_z), el componente ya está saturado
cerca de 1 para cualquier ZSaturation∈{1,2,3} — subir ZSaturation
ayuda a los casos borderline (combined cerca de 0.375-0.45), pero no
puede arreglar los más extremos (combined 0.55-0.65) por sí solo.

**Hallazgo adicional, no pedido pero relevante**: en casi todas las
filas, `failed_auth_ratio_z` y `account_diversity_ratio_z` son
IDÉNTICOS. Son dos features distintas en el modelo, pero en esta
población legítima concreta (aparenta ser tráfico tipo API client)
están perfectamente correlacionadas — el modelo las cuenta dos veces
como si fueran evidencia independiente, inflando el combined score
más de lo que un observador esperaría de "5 señales independientes".
No se propone tocar pesos (fuera del alcance acordado), pero explica
por qué el combined score de estos FP es más alto de lo que la
intuición sobre 5 features independientes sugeriría.

Distribución completa (0% malicious, ambas acciones):

| Action | N | Combined (p50/p75/p90/p95/max) | RiskScore (p50/p75/p90/p95/max) |
|---|---|---|---|
| ALLOW | 3331 | 0.0735/0.1789/0.2365/0.2777/**0.3749** | 0.0000/0.3424/0.3891/0.4220/0.4999 |
| CHALLENGE | 164 | **0.3758**/0.4421/0.4828/0.6046/0.6349 | 0.5006/0.5537/0.5862/0.6837/0.7079 |

### 2. Campañas de slow_scan — MinRequests NO es el problema a 30%; NovelPathRatio sí

**A 10% (6 campañas, las 3 seeds)**: 100% detectadas, TODAS
exactamente en el request #15, con `TotalRequests(14<15)` como única
condición limitante justo antes — las otras 4 condiciones del gate ya
estaban satisfechas mucho antes. Tamaño de campaña: min=29 p50=45
max=56 — MinRequests nunca es un problema real acá, es solo el último
en cruzar.

**A 30% (27 campañas)**: usando el disparo PROPIO del gate de
slowscan (`SlowScan.Triggered`, no la Decision final combinada — ver
nota abajo), solo 13 de 27 campañas (48%) cruzan el gate alguna vez.
De las 14 que nunca lo cruzan, **las 14 tienen `NovelPathRatio` como
única condición limitante** (valores entre 0.00 y 0.48, todos por
debajo del mínimo 0.50) — nunca `TotalRequests`. Tamaño de campaña a
30%: min=20 p50=44 max=60 — prácticamente la MISMA distribución de
tamaño que a 10% (mediana 44 vs 45): **la degradación NO es porque
las campañas sean más chicas**, es específicamente `NovelPathRatio`.

**Mecanismo, verificado contra el código real del generador**:
`internal/datagen/slowscan.go` elige cada ruta con
`Pick(rng, profile.SensitivePaths)` de un vocabulario COMPARTIDO de
solo 30 rutas (`internal/datagen/paths.go`) — el mismo para las 2
campañas de 10% y las 9 de 30%. Con 9 escáneres independientes en vez
de 2, sorteando de las mismas 30 rutas, es mucho más probable que 3 o
más IPs de escáneres DISTINTOS visiten la misma ruta dentro de la
ventana — y `MaxVisitorsForNovelPath=2` hace que esa ruta deje de
contarse como "novel" para NINGUNO de ellos, aunque sea comportamiento
de escaneo genuino. No es "más fragmentación de ataque", es
**contaminación cruzada del índice de popularidad de rutas** entre
campañas simultáneas, agravada por que el pool de rutas nunca crece
aunque haya más atacantes.

**Nota importante sobre "detectada" (eventual campaign detection)**:
esta sección usa `SlowScan.Triggered` (el gate propio de slowscan) —
por eso da números más bajos (13/27 = 48%) que el
`ss_eventual_detection_rate` del Punto de Control 1 (89%-100%), que
usa la Decision FINAL combinada (cualquier detector, típicamente
statistical_anomaly "rescatando" la campaña). Son preguntas
distintas: ¿el gate de slowscan cruzó alguna vez? vs. ¿el motor
completo terminó marcando la campaña alguna vez, sin importar por
qué? La primera es la que hace falta para saber si calibrar
slowscan tiene sentido.

### 3. Distribución de RiskScore por detector — por qué BlockThreshold=0.80 casi nunca dispara

| Detector | Grupo | N | p50 | p75 | p90 | p95 | max |
|---|---|---|---|---|---|---|---|
| credential_stuffing | legit | 10485 | 0 | 0 | 0 | 0 | 0 |
| slow_scan | legit | 10485 | 0 | 0 | 0 | 0 | 0 |
| statistical_anomaly | legit | 10485 | 0 | 0.3401 | 0.3943 | 0.4630 | 0.7079 |
| credential_stuffing | malicious | 608 | 0 | 0.5699 | 0.6140 | 0.6365 | **0.6683** |
| slow_scan | malicious | 1383 | 0 | 0.6777 | 0.7834 | **0.8103** | **0.8467** |
| statistical_anomaly | malicious (cualquier ataque) | 1991 | 0.4818 | 0.5267 | 0.6063 | 0.6422 | 0.6958 |

Ningún detector, en la práctica, se acerca a 0.80 salvo el 5%-10% más
extremo de `slow_scan` (p90=0.78, p95=0.81) — `credential_stuffing`
nunca supera 0.6683 en estos datos, `statistical_anomaly` nunca supera
0.6958. `BlockThreshold=0.80` está calibrado por encima de lo que
estas fórmulas de score pueden producir salvo en el caso más extremo
de slow_scan — coherente con el `strict_recall` casi nulo del Punto de
Control 1. Esto es contexto para la calibración de Policy, que
todavía no se toca.

### 4. Credential stuffing — sin cambios propuestos

Confirmado: 0 RiskScore en el 100% del tráfico legítimo (cero riesgo
de falso positivo), recall 84%-98% ya visto en el Punto de Control 1,
sin ningún error concreto encontrado en esta pasada. No se propone
ningún candidato para este detector.

### 5. 30% vs 10%: qué cambia realmente

Documentado explícitamente, con datos: al pasar de 10% a 30% la
cantidad de campañas de slow_scan sube de 2 a 9 por escenario, pero el
TAMAÑO de cada campaña (min/p50/max) es prácticamente el mismo. La
comparación entre ratios introduce más campañas SIMULTÁNEAS
compitiendo por el mismo vocabulario de rutas sensibles, degradando
`NovelPathRatio` por contaminación cruzada — no una distribución de
ataque "más fragmentada" en el sentido de campañas más chicas. El
generador no se tocó.

### Candidatos propuestos para el próximo paso — todavía SIN ejecutar

**Slow Scan** (ninguno cambia `MinRequests`: se confirmó que no es el
gate limitante a ninguna ratio):

| Candidato | Cambio | Error que corrige |
|---|---|---|
| `slowscan-maxvisitors-3` | `MaxVisitorsForNovelPath`: 2→3 | Ataca el MECANISMO: tolera una IP más antes de que una ruta compartida deje de contar como "novel" — directamente compensa la contaminación cruzada de 9 campañas simultáneas. |
| `slowscan-novelratio-0.35` | `MinNovelPathRatio`: 0.50→0.35 | Ataca el GATE directamente — como `slow_scan` tiene RiskScore=0 en el 100% del tráfico legítimo hoy, hay margen real para relajar este umbral sin (todavía) evidencia de que introduzca FP. |
| `slowscan-maxvisitors-3-novelratio-0.35` | Los dos combinados | Ver si se refuerzan o si uno solo ya alcanza — evita commitear a dos cambios si uno basta. |

**Statistical Anomaly** — grid pedido, con expectativa explícita antes
de correrlo (para poder comparar predicción vs. resultado real):

| Candidato | Cambio | Expectativa, según el análisis de esta pasada |
|---|---|---|
| `anomaly-z1` | ZSaturation 2→1 | Se espera que EMPEORE (más FP) — confirmado a mano arriba. Se incluye para completar el grid pedido y confirmarlo empíricamente, no porque se espere que gane. |
| `anomaly-z3` | ZSaturation 2→3 | Se espera una mejora PARCIAL — reduce combined en los casos borderline (cerca de 0.375-0.45), no en los más extremos (0.55-0.65). |
| `anomaly-trigger-010` / `anomaly-trigger-020` | TriggerThreshold 0.15→0.10/0.20 | Se espera CASI NINGÚN efecto sobre estos 164 FP específicos — todos tienen combined ≥0.3758, muy por encima de cualquier valor de este grid. Se incluye para confirmarlo (o refutarlo) con datos, y porque sí afecta qué cuenta como "Triggered" para las métricas de `waf.detector.findings_total` y para detectar si algún caso límite sí se ve afectado. |
| `anomaly-z3-trigger-020` | Los dos combinados | La combinación más prometedora según el análisis — ZSaturation hace el trabajo real, TriggerThreshold es principalmente para consistencia. |

Ningún candidato se ejecutó todavía. Se espera aprobación antes de
correr cualquiera de estos contra los datos de tuning.

## 2026-09-28 — Sweep de detectores sobre tuning (tarea 1.9)

Ejecutado con `go run ./cmd/sweep` — solo tuning (seeds 101/102/103,
ratios 0/10/30%), nunca holdout. `ScoreFloor`, `ChallengeThreshold`,
`BlockThreshold` y `credential_stuffing` sin tocar. Reportes completos
(por seed y agregados): `reports/tuning/sweep-slowscan.md` y
`reports/tuning/sweep-anomaly.md`.

### Infraestructura nueva

`internal/tuning/sweep_slowscan.go` y `sweep_anomaly.go`: agregación
entre seeds (media de cada `Ratio` definido, nunca tratando N/A como
0), `AnomalyTriggerBreakdown` (Triggered@0% separado por Action
final), `CompareAnomalyTransitions` (compara la MISMA corrida entre
baseline y un candidato, evento por evento, y clasifica cada FP de
baseline en "dejó de Triggered" / "sigue Triggered pero ahora ALLOW" /
"sigue sin resolver"). `cmd/sweep` orquesta ambos sweeps sobre los
mismos 9 escenarios (generados una sola vez, compartidos entre
candidatos, para que la comparación sea exacta).

### Resultado — Slow Scan

| Candidato | FPR@0% | BroadRecall@30% | SSRecall@30% | EventualDet@30% (gate propio) |
|---|---|---|---|---|
| S0 baseline | 0.0472 | 0.4940 | 0.3050 | 0.4815 |
| S1 maxvisitors-3 | 0.0472 (=) | 0.6456 | 0.5238 | 0.7407 |
| S2 novelratio-035 | 0.0472 (=) | 0.5566 | 0.3954 | 0.5926 |
| S3 ambos | **0.0472 (=)** | **0.6757** | **0.5669** | **0.8519** |

**FPR@0% y todo @10% quedaron IDÉNTICOS en los 4 candidatos** — ni un
solo cambio, en ningún seed. Es lo que predecía el Punto de Control 2
(`slow_scan` tiene RiskScore=0 en el 100% del tráfico legítimo; a
10% las 2 campañas por seed ya se detectan por `MinRequests`, nunca
por `NovelPathRatio`) y quedó confirmado con datos reales, no solo
teorizado. `Req.medio/mediana@30%` se mantiene ~15 en los cuatro —
la mejora es enteramente de COBERTURA (más campañas cruzan el gate
alguna vez), no de velocidad.

### Resultado — Statistical Anomaly

| Candidato | FP@0% (avg) | FPR@0% (avg) | BroadRecall@10%(avg) | BroadRecall@30%(avg) | Recall CS@10% (min–max entre seeds) |
|---|---|---|---|---|---|
| A0 baseline | 54.7 | 0.0472 | 0.8752 | 0.4940 | 0.842–0.977 |
| A1 z3 | 26.0 | 0.0225 | 0.7321 | 0.3722 | **0.553**–0.954 |
| A2 trigger020 | 40.3 | 0.0350 | 0.8205 | 0.4418 | 0.842–0.977 (≈ igual) |
| A3 account-weight05 | 44.3 | 0.0384 | **0.9230** | **0.6717** | 0.737–0.954 |
| A4 z3+weight05 | 19.0 | 0.0164 | 0.7386 | 0.3705 | **0.342**–0.930 |
| A5 z3+trigger020 | 12.0 | 0.0104 | 0.7297 | 0.3722 | 0.526–0.954 |

**Hallazgo central, en los tres seeds, los cinco candidatos, sin
excepción**: "Dejó de Triggered" = **0** siempre — ningún candidato
hace que una evaluación de anomaly deje de disparar del todo. El
100% de la reducción de FP viene de "sigue Triggered, pero la Action
final pasa a ALLOW" (el RiskScore baja de 0.50, no de 0.20) —
confirma exactamente el mecanismo ya identificado en el Punto de
Control 2 (el límite real es ScoreFloor+Challenge≈0.375 en espacio de
combined, muy por encima de cualquier TriggerThreshold del grid).

**Hallazgo no anticipado**: `ZSaturation=3` (A1, y A4/A5 que lo
incluyen) reduce FP con fuerza, pero **daña recall de forma
inestable entre seeds** — el caso más claro: `Recall
credential_stuffing@10%` del seed 101 cae de 0.842 (baseline) a
**0.553** en A1 y a **0.342** en A4. Esto pasa porque
`statistical_anomaly`, aunque nunca sea "el" vector, hoy contribuye
recall EXTRA sobre eventos de credential_stuffing/slow_scan (los
marca como positivos incluso antes de que el gate propio de esos
detectores cruce) — bajar la sensibilidad general de anomaly le
quita esa cobertura adicional, y el efecto es desigual entre seeds
(inestable), no un trade-off limpio y previsible.

**Hallazgo no anticipado (positivo)**: `AccountDiversityWeight=0.5`
(A3) mejora recall en vez de sacrificarlo (BroadRecall@30% sube de
0.494 a 0.672) — la reducción del peso, al reducir también el
denominador de la normalización, redistribuye sensibilidad hacia el
resto de las features en vez de solo apagar la que correlaciona con
`failed_auth` (el hallazgo del Punto de Control 2). FP baja menos
(19% vs. el 52% de A1) pero sin ningún costo de recall — de hecho con
una ganancia.

### Selección — sin combinar, sin tocar Policy, sin holdout

**Slow Scan: se propone S3** (`MaxVisitorsForNovelPath=3` +
`MinNovelPathRatio=0.35`). Domina a S1 y S2 en todos los ejes medidos
— mismo FPR@0% (0.0472, sin cambio), mismo comportamiento @10%, mejor
recall/detección eventual @30% de los cuatro (0.676 / 0.567 / 0.852)
— sin ningún trade-off identificado. S1 solo es la alternativa más
simple (un solo parámetro) si se prefiere un cambio más chico, pero
S3 no cuesta nada adicional sobre S1.

**Statistical Anomaly: se propone A3** (`AccountDiversityWeight=0.5`
únicamente). Es el único candidato que MEJORA recall en vez de
dañarlo (broad@30% +36% relativo), con una reducción de FP real
aunque modesta (19%), y con estabilidad entre seeds razonable (ningún
seed se desvía de forma extrema). Se descartan A1/A4/A5 pese a su
mayor reducción de FP (hasta 78% en A5) porque dañan recall de forma
seria e IRREGULAR entre seeds — en particular, la caída de recall de
credential_stuffing a 0.34–0.55 en algunos seeds es un costo
demasiado alto e impredecible para una mejora de FP que, de todos
modos, no llega a eliminar el problema (nunca "deja de Triggered").
A2 es la alternativa conservadora si se prefiere tocar menos: FP baja
26% con daño de recall mínimo, pero bastante menos ambicioso que A3.

Ningún candidato se combinó. `Policy` no se tocó. No se usó holdout.
Se espera aprobación antes de seguir.

## 2026-09-28 — Sweep combinado C0–C3 (tarea 1.9)

Ejecutado con `go run ./cmd/sweepcombined` — solo tuning, nunca
holdout. `credential_stuffing`, `ScoreFloor`, `ChallengeThreshold` y
`BlockThreshold` sin tocar. Reporte completo:
`reports/tuning/sweep-combined.md`. S3 (`MaxVisitorsForNovelPath=3` +
`MinNovelPathRatio=0.35`) queda como base común de los tres
candidatos no-baseline — todavía sin congelar.

### Infraestructura nueva

`internal/tuning/attribution.go` (`ComputeMitigationAttribution`):
para cada evento MITIGADO de un vector, clasifica si disparó su
propio detector, si también disparó `statistical_anomaly`, si
dependió únicamente de `anomaly`, o si fue una señal cruzada — sin
ninguna corrida nueva, reutiliza los Finding crudos que ya expone
`RunDiagnostics`. `internal/tuning/sweep_combined.go`: agrega
`RunResult`/`DelaySummary`/atribución en una fila por
candidato×seed, con promedios entre seeds.

### Hallazgo estructural, no buscado pero central: credential_stuffing nunca mitiga solo

En los 4 candidatos, en los 3 seeds, sin ninguna excepción:
`DetectorOnly` de `credential_stuffing` es **0** siempre. A 10%, el
100% de sus eventos mitigados dependen ÚNICAMENTE de
`statistical_anomaly` (`AnomalyOnly`); a 30%, ~33% dependen solo de
anomaly y ~67% tienen a los dos disparando juntos
(`WithAnomalyAssist`) — pero el propio gate de `credential_stuffing`
JAMÁS dispara sin que anomaly también lo haga. La causa más probable:
`credential_stuffing.Window=30min` es mucho más corta que
`StuffingWindow=3h` (la campaña se genera repartida en 3 horas) — en
cualquier ventana de 30 minutos, las ~20-77 IPs atacantes rara vez se
concentran lo suficiente como para que `MinDistinctIPs=20` cruce por
sí solo. La conclusión de la tarea 0.9/Punto de Control 2 ("credential
stuffing funciona sólido, no necesita cambios") medía la Decision
FINAL, no quién la producía — con esta nueva evidencia, ese recall es
en gran parte prestado de `statistical_anomaly`, no del propio
detector correlacionado. No se toca nada de esto ahora (fuera de
alcance explícito de este paso), pero queda documentado porque
cambia cómo hay que leer cualquier costo de recall de
`credential_stuffing` en los candidatos de abajo: ese costo es, casi
siempre, un costo a la AYUDA que anomaly le presta a
credential_stuffing, no un daño al propio detector correlacionado.

Para `slow_scan`, el mismo patrón se sostiene en C0/C1/C2
(`DetectorOnly=0` siempre) — pero en **C3** (`TriggerThreshold=0.20`)
aparece `DetectorOnly=123` de 541 a 30% (23%): al exigirle más
evidencia a anomaly antes de disparar, algunas detecciones de
slow_scan pasan a depender solo de su propio gate por primera vez.

### Resultados agregados (promedio de 3 seeds)

| Candidato | FPR@0% | BroadRecall@30% | Precision@30% | F1@30% | Recall CS@30% | Recall SS@30% |
|---|---|---|---|---|---|---|
| C0 baseline (S0+A0) | 0.0472 | 0.4940 | 0.9067 | 0.6361 | 0.9267 | 0.3050 |
| C1 slowscan-only (S3+A0) | 0.0472 (=) | 0.6757 | 0.9297 | 0.7757 | 0.9267 (=) | 0.5669 |
| C2 slowscan+account-weight (S3+A3) | 0.0384 | **0.7503** | 0.9468 | **0.8292** | 0.8985 | **0.6862** |
| C3 slowscan+trigger020 (S3+A2) | **0.0350** | 0.6303 | 0.9566 | 0.7545 | **0.9267 (=)** | 0.5013 |

### C2 vs. C3 — el contraste pedido explícitamente

- **Falsos positivos**: C3 levemente mejor (FPR 0.0350 vs 0.0384) —
  diferencia chica, del orden de la variabilidad normal entre seeds.
- **Recall general (broad@30%)**: C2 claramente mejor (0.750 vs
  0.630, +12 puntos).
- **Recall credential_stuffing@30%**: C3 no tiene NINGÚN costo
  (0.9267, igual que baseline) — C2 cuesta ~3 puntos (0.8985). Dado
  el hallazgo de arriba, este costo es específicamente la asistencia
  de anomaly a credential_stuffing volviéndose un poco menos
  frecuente, no el propio detector correlacionado empeorando.
- **Recall slow_scan@30%**: C2 gana con claridad (0.686 vs 0.501,
  +18.5 puntos) — es la métrica que motivó todo este sweep, y C2 la
  resuelve mucho mejor.
- **Estabilidad entre seeds**: ninguno de los dos es perfectamente
  estable — `Recall SS@30%` por seed es 0.738/0.884/0.438 en C2
  (rango 0.45) y 0.409/0.693/0.403 en C3 (rango 0.29, pero con
  valores centrales más bajos). `Recall CS@30%` es más estable en
  ambos (C2: 0.872/0.934/0.890; C3: 0.872/0.961/0.948).

**Lectura, sin elegir automáticamente**: C2 es la opción más fuerte
para el objetivo original de este sweep (recall de slow_scan) y para
recall general, a cambio de un costo chico y mecánicamente explicado
en credential_stuffing (vía la asistencia de anomaly, no el detector
en sí) y una FPR apenas mayor. C3 es la opción "no tocar
credential_stuffing bajo ninguna circunstancia", pero deja gran parte
del problema original de slow_scan sin resolver.

Nada se congeló. `ScoreFloor` y `Policy` sin tocar. No se usó
holdout. Se espera aprobación antes de seguir.

## 2026-09-28 — Diagnóstico de credential_stuffing: ventana real vs. ground truth (tarea 1.9)

C2 (S3+A3) aprobado como líder provisional, sin congelar. Antes de
tocar `ScoreFloor`/Policy, se investigó el hallazgo del sweep
combinado (`credential_stuffing` nunca aparece como `DetectorOnly`).
Ejecutado con `go run ./cmd/diagnosecs`, usando C2 tal cual (S3/A3 sin
tocar) — reporte completo:
`reports/tuning/diagnose-credstuffing.md`.

### Infraestructura nueva

`credstuffing.Detector.EvaluateGateMetrics` (+ `GateMetrics`): mismo
patrón que `slowscan`/`anomaly` — expone `DistinctIPs`,
`DistinctAccounts`, `TotalAttempts`, `FailedRatio` SIN IMPORTAR si el
gate disparó. `evaluateGroup` se refactorizó para llamar al mismo
`gateMetricsFor` interno — una sola fórmula, comportamiento
verificado idéntico (todos los tests existentes en verde + 3
nuevos). `internal/tuning/diagnose_credstuffing.go`
(`AnalyzeCredentialStuffingCampaigns`): agrupa por seed+ratio+grupo de
red, calcula el MÁXIMO de cada señal del gate observado en
CUALQUIER momento de la campaña (nunca el total ground truth), y
compara contra los thresholds actuales.

### El diagnóstico, con datos reales

| Seed | Ratio | Requests | IPs totales | Cuentas totales | Max ventana IPs (min 20) | Max ventana Cuentas (min 15) | Max ventana Attempts (min 25) | Gates limitantes | Detectada (gate propio) |
|---|---|---|---|---|---|---|---|---|---|
| 101 | 10% | 38 | 20 | 36 | 9 | 10 | 11 | IPs, Accounts, Attempts | **false** |
| 102 | 10% | 43 | 19 | 43 | 12 | 15 | 15 | IPs, Attempts | **false** |
| 103 | 10% | 47 | 20 | 46 | 13 | 13 | 14 | IPs, Accounts, Attempts | **false** |
| 101 | 30% | 156 | 76 | 149 | 32 | 36 | 37 | (ninguno) | **true** (req. #25) |
| 102 | 30% | 152 | 73 | 148 | 34 | 36 | 37 | (ninguno) | **true** (req. #25) |
| 103 | 30% | 172 | 76 | 165 | 33 | 39 | 40 | (ninguno) | **true** (req. #42) |

`FailedRatio` nunca es limitante en ninguna campaña (siempre 1.00 vs
mínimo 0.60 — funciona correctamente, no se toca).

**A 30% no hay ningún gate limitante — el detector SÍ dispara solo**,
alrededor del request #25-42 de 152-172. La hipótesis de "la ventana
es el problema" NO se sostiene acá: simplemente hay suficiente
densidad de tráfico dentro de cualquier ventana de 30 minutos.

**A 30%, el atributo "0% Credential only" no es un fallo del
detector**: una vez que su gate cruza, CADA evento restante también
tiene a `statistical_anomaly` disparando en simultáneo — coinciden,
en vez de que credential_stuffing haga el trabajo solo. Esto explica
el `DetectorOnly=0` del sweep anterior en un sentido MENOS alarmante
de lo que parecía: el detector SÍ funciona a 30%, solo que nunca le
toca "ganar" en soledad porque anomaly ya está activo para ese mismo
tramo de la campaña.

**A 10%, la hipótesis SÍ se confirma, pero de forma más precisa que
"Window=30min + MinDistinctIPs=20"**: los TOTALES completos de la
campaña (19-20 IPs a lo largo de las ~3 horas enteras) ya están
apenas EN el umbral — ni siquiera una ventana que cubriera la
campaña completa garantizaría cruzar `MinDistinctIPs=20` con margen.
Además, **`MinDistinctAccounts` y `MinAttempts` también están
limitando simultáneamente** en 2 de 3 seeds — no es un problema de un
solo gate, es que el volumen total que el 10% de tráfico malicioso
genera para esta campaña está muy cerca (IPs) o holgadamente por
debajo (ventana de Accounts/Attempts) de los tres umbrales a la vez.

Distribución del máximo de DistinctIPs por ventana, tal como se pidió
por ser el gate más consistentemente limitante:

- Todas las campañas: N=6, min=9, p50=13, p95=34, max=34.
- **Solo 10%**: N=3, min=9, p50=12, max=13 — ninguna se acerca
  remotamente a 20.
- **Solo 30%**: N=3, min=32, p50=33, max=34 — todas superan 20
  cómodamente.

Una distribución claramente bimodal: no hay un punto intermedio
"casi cruza" — o el gate cruza con margen amplio, o se queda muy
lejos.

### Candidatos propuestos para Credential Stuffing — todavía SIN ejecutar

Se evita tocar `MinDistinctAccounts`, `MinAttempts` y
`MinFailedRatio` de forma aislada: no son el limitante más
consistente (Accounts/Attempts solo limitan a 10%, y son síntoma del
mismo déficit de volumen que IPs, no un problema propio;
FailedRatio funciona bien siempre). Solo se consideran
`MinDistinctIPs` y `Window`, según lo autorizado:

| Candidato | Cambio | Expectativa explícita, antes de correrlo |
|---|---|---|
| `CS1-window-60m` | `Window`: 30min→60min | Se espera una mejora PARCIAL, insuficiente sola: duplicar la ventana debería acercar el máximo observado a los totales de la campaña (19-20), pero eso sigue estando muy cerca del umbral actual (20) — probablemente no cruce con margen en los 3 seeds. |
| `CS2-mindistinctips-15` | `MinDistinctIPs`: 20→15 | Se espera que TAMPOCO alcance solo: el máximo observado a 10% (9, 12, 13) sigue por debajo de 15 en los TRES seeds con la ventana actual — bajar el umbral sin tocar la ventana no alcanza con estos datos. |
| `CS3-window-60m-mindistinctips-15` | Los dos combinados | El candidato que efectivamente se espera que funcione: la ventana más ancha debería acercar el máximo observado a los totales (19-20), y un umbral de 15 (no 20) da margen real para cruzar en los 3 seeds sin necesitar el total exacto de la campaña. |

Advertencia explícita para cuando se ejecuten: bajar `MinDistinctIPs`
tiene que revisarse contra `FPR@0%` en la siguiente corrida — nunca
se asumió que estos datos por sí solos garanticen que no aparezcan
falsos positivos nuevos, eso se mide, no se da por sentado.

No se ejecutó ningún candidato. `S3`, `A3`, `ScoreFloor`,
`ChallengeThreshold`, `BlockThreshold` sin tocar. No se usó holdout.
Se espera aprobación antes de seguir.

## 2026-09-28 — Sensibilidad de credential_stuffing a Window: verificación offline antes del sweep (tarea 1.9)

Antes de aprobar el sweep de Credential Stuffing, se pidió una
corrección al diagnóstico anterior: `MinAttempts=25` también es un
gate consistentemente limitante a 10% (11, 15, 14 — los tres por
debajo de 25 con `Window=30min`), algo que el análisis previo no
había señalado como igual de central que `MinDistinctIPs`. Se pidió
recalcular, offline y sin tocar ningún threshold ni el detector de
producción, el máximo rolling de las cuatro señales del gate con
`Window=30min` (producción), `60min` y `90min`, usando exactamente
los mismos eventos de las tres campañas al 10%.

### Infraestructura nueva

`internal/tuning/window_sensitivity.go`: `WindowSensitivityRow`,
`AnalyzeWindowSensitivity(scenario, resolver, baseCfg, windows)` —
construye, por cada duración en `windows`, un `credstuffing.Detector`
propio y limpio (misma `Config` que `baseCfg`, solo cambia `Window`)
y lo corre sobre **todos** los eventos del escenario (igual que
`RunDiagnostics`: el detector real también observa tráfico legítimo
del mismo grupo de red, no solo el malicioso), registrando el máximo
histórico de cada señal únicamente en los eventos etiquetados
`credential_stuffing`. `RenderWindowSensitivity` arma el reporte.
Cubierto por `window_sensitivity_test.go` (2 tests: que una ventana
más ancha nunca baja el máximo, y que `Observe` sí procesa tráfico
legítimo aunque el máximo solo se mida en eventos CS-etiquetados).
`cmd/diagnosecswindow` corre esto sobre los seeds 101/102/103 al 10%
con el candidato C2 (S3+A3, thresholds de credential_stuffing
iguales al baseline) y escribe
`reports/tuning/diagnose-cs-window.md`. Suite completa
(`gofmt`/`go vet`/`go test`/`go test -race`) en verde después de
agregar esto.

### El resultado, con datos reales

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

Respuestas a las cuatro preguntas planteadas:

1. **¿60m por sí sola hace cruzar Accounts/Attempts?** Accounts sí,
   en los tres seeds (17, 23, 21 ≥ 15). Attempts NO, en ninguno de
   los tres (18, 23, 22 — los tres por debajo de 25).
2. **¿Qué gates siguen fallando con 60m?** `MinDistinctIPs` (14, 16,
   19 — los tres por debajo de 20) y `MinAttempts` (18, 23, 22 — los
   tres por debajo de 25), en los tres seeds sin excepción.
   `MinDistinctAccounts` y `MinFailedRatio` ya no limitan a 60m.
3. **¿90m cruza todos los gates actuales?** NO. `MinDistinctIPs`
   sigue sin cruzar en NINGÚN seed incluso a 90m (16, 18, 19 — los
   tres por debajo de 20: ensanchar la ventana ayuda pero no alcanza
   ni al triple de duración de producción). `MinAttempts` cruza en 2
   de 3 seeds a 90m (30, 28 ≥ 25) pero sigue fallando en el seed 101
   (24 < 25, por un solo intento).
4. **¿Cambio mínimo que permite detectar las tres campañas al 10%
   sin tocar más thresholds de los necesarios?** Ensanchar
   únicamente la ventana (aun a 90m) NO alcanza — `MinDistinctIPs`
   queda estructuralmente por debajo del umbral en los tres seeds
   sin importar cuánto se ensanche dentro de lo razonable, y
   `MinAttempts` sigue fallando en uno de tres seeds incluso a 90m.
   Hace falta combinar `Window` con una reducción de **ambos**
   `MinDistinctIPs` y `MinAttempts` — no alcanza con uno solo de los
   dos, la corrección del enunciado sobre `MinAttempts` resultó
   correcta. `MinDistinctAccounts` y `MinFailedRatio` no necesitan
   tocarse: ya cruzan solos con `Window=60min` en los tres seeds (o,
   en el caso de `MinFailedRatio`, ya cruzan siempre, sin importar la
   ventana).

### Candidatos revisados para Credential Stuffing — reemplazan a CS1/CS2/CS3, todavía SIN ejecutar

Los candidatos `CS1`/`CS2`/`CS3` de la sección anterior quedan
descartados sin ejecutar: `CS3-window-60m-mindistinctips-15`
suponía que 60m alcanzaba para Accounts/Attempts, pero los datos
muestran que Attempts sigue fallando a 60m en los tres seeds — ese
candidato específico no habría funcionado. Los siguientes tres
candidatos usan directamente los máximos observados a 90m (el mínimo
entre los tres seeds, para que los tres crucen):

| Candidato | Cambio | Expectativa explícita, antes de correrlo |
|---|---|---|
| `CSw1-window-90m` | `Window`: 30min→90min, sin tocar ningún threshold | Confirma que la ventana sola NO alcanza: `MinDistinctIPs` (16/18/19 vs 20) y, en el seed 101, `MinAttempts` (24 vs 25) siguen sin cruzar. Se incluye como control, no como candidato final. |
| `CSw2-window-90m-mindistinctips-16` | `Window`→90min + `MinDistinctIPs`: 20→16 (el mínimo de los tres máximos observados a 90m: 16, 18, 19) | Cierra el gate de IPs en los tres seeds, pero `MinAttempts` sigue fallando en el seed 101 (24<25) — se espera insuficiente todavía. |
| `CSw3-window-90m-mindistinctips-16-minattempts-24` | `Window`→90min + `MinDistinctIPs`: 20→16 + `MinAttempts`: 25→24 (el mínimo de los tres máximos observados a 90m: 24, 30, 28) | El candidato que se espera que efectivamente detecte las tres campañas al 10% — los cuatro gates cruzan con los máximos reales observados. `MinDistinctAccounts` y `MinFailedRatio` quedan sin tocar. |

Advertencia explícita, para cuando se ejecuten: `MinDistinctIPs=16`
y `MinAttempts=24` están fijados en el mínimo exacto observado entre
solo 3 seeds de tuning — sin ningún margen. Esto es deliberadamente
agresivo para poder medir el trade-off real contra `FPR@0%` en la
próxima corrida, no una recomendación final; es muy posible que el
valor que finalmente se elija termine con algo de margen por encima
de estos mínimos, una vez visto el impacto en falsos positivos.

No se ejecutó ningún candidato. `S3`, `A3`, `ScoreFloor`,
`ChallengeThreshold`, `BlockThreshold` sin tocar. No se usó holdout.
Se espera aprobación antes de seguir.

## 2026-09-28 — Sweep de Credential Stuffing: CS0–CSw4 (tarea 1.9)

Se aprobó ejecutar el sweep de credential_stuffing, con la precisión
de que `MinDistinctIPs=16` y `MinAttempts=24` (usados en `CSw3`) son
mínimos derivados de solo 3 seeds de tuning — un candidato
experimental agresivo, no una configuración final. Se corrieron 5
candidatos sobre tuning (seeds 101/102/103, ratios 0/10/30%), todos
partiendo de C2 (S3+A3) para slow_scan/anomaly — sin tocar esos dos
detectores, `ScoreFloor`, `Policy` ni usar holdout:

| Candidato | Window | MinDistinctIPs | MinAttempts | MinDistinctAccounts | MinFailedRatio |
|---|---|---|---|---|---|
| `CS0-baseline` | 30m | 20 | 25 | 15 | 0.60 |
| `CSw1-window90` | 90m | 20 | 25 | 15 | 0.60 |
| `CSw2-window90-ips16` | 90m | 16 | 25 | 15 | 0.60 |
| `CSw3-window90-ips16-attempts24` | 90m | 16 | 24 | 15 | 0.60 |
| `CSw4-conservative` | 90m | 18 | 25 | 15 | 0.60 |

### Infraestructura nueva

`internal/tuning/sweep_credstuffing.go`: `CredentialStuffingSweepRow`
(FPR@0%, precision/F1/recall broad @10/30, recall de
credential_stuffing **detector-específico** —
`credentialStuffingDetectorRecall`, request-level sobre
`CredentialStuffing.Triggered` — mantenido separado del recall
**decision-based** existente, detección eventual de campaña y
requests/tiempo a esa detección vía el gate propio —
`csDetectionStats`, nunca promedia campañas no detectadas — y
atribución credential-only/anomaly-only/both/neither pooled sobre
conteos crudos, nunca sobre porcentajes ya redondeados de campañas de
distinto tamaño — `pooledAttributionPct`), `ComputeCredentialStuffingSweepRow`,
`AggregateCredentialStuffingSweepRows`, `RenderCredentialStuffingSweep`.
Se extendió `CredentialStuffingCampaignAnalysis` (en
`diagnose_credstuffing.go`) con `TimeToFirstDetection` (N/A-seguro) y
los conteos crudos `CredOnlyEvents`/`AnomOnlyEvents`/`BothEvents`/`NeitherEvents`
detrás de cada `Pct*` — necesarios para agregar varias campañas sin
perder precisión. Cubierto por 6 tests nuevos en
`sweep_credstuffing_test.go`. `cmd/sweepcs` corre los 5 candidatos y
escribe `reports/tuning/sweep-credstuffing.md`. Suite completa
(`gofmt`/`go vet`/`go test`/`go test -race`) en verde antes y después
de correr el sweep real.

### Resultado — métricas generales (broad, overall, promedio de 3 seeds)

| Candidato | FPR@0% | Precision@30% | F1@30% | BroadRecall@30% | StrictRecall@30% (BLOCK) |
|---|---|---|---|---|---|
| CS0-baseline | 0.0384 | 0.9468 | 0.8292 | 0.7503 | 0.0805 |
| CSw1-window90 | 0.0384 | 0.9476 | 0.8389 | 0.7647 | 0.2264 |
| CSw2-window90-ips16 | 0.0384 | 0.9476 | 0.8389 | 0.7647 | 0.2589 |
| CSw3-window90-ips16-attempts24 | 0.0384 | 0.9476 | 0.8389 | 0.7647 | 0.2615 |
| CSw4-conservative | 0.0384 | 0.9476 | 0.8389 | 0.7647 | 0.2498 |

**Hallazgo importante: `FPR@0%` es IDÉNTICO en los 5 candidatos**
(0.0186/0.0626/0.0340 por seed, sin variar). En el escenario 0% de
este generador no hay tráfico legítimo que se parezca lo suficiente a
credential stuffing (mismo ASN, mismo endpoint de auth, volumen alto)
como para que bajar estos umbrales dispare ningún FP nuevo. Esto NO
debe leerse como "es seguro bajar los umbrales" en términos
absolutos — es una limitación conocida del dataset sintético actual,
no una garantía: el FPR@0% de este sweep solo demuestra que
`MinDistinctIPs=16`/`MinAttempts=24` no rompen nada CONTRA ESTE
generador, no que sean seguros contra tráfico legítimo real con
patrones de login de alto volumen (por ejemplo, un servicio interno
con reintentos automáticos).

`BroadRecall@30%` y `Precision@30%`/`F1@30%` mejoran de forma
prácticamente IDÉNTICA en los 4 candidatos con `Window=90m` frente al
baseline (0.7503→0.7647) — el salto lo produce ensanchar la ventana,
no los ajustes de `MinDistinctIPs`/`MinAttempts` sobre ella: una vez
que la ventana es suficiente, `statistical_anomaly` ya cubre casi
todo lo que falta a nivel Decision, igual que documentó el diagnóstico
anterior. Donde SÍ hay diferencia entre los 4 candidatos con Window=90m
es en `StrictRecall@30%` (BLOCK puro): `CSw3` es el mejor (0.2615),
seguido de `CSw2` (0.2589) y `CSw4` (0.2498) — bajar los umbrales
ayuda a que el RiskScore de credential_stuffing cruce
`BlockThreshold=0.80` más seguido, aun cuando no cambie mucho el
recall broad general.

### Resultado — recall detector-específico vs. decision-based, y detección eventual @10%

| Candidato | RecallDetector@10% | RecallDetector@30% | EventualDet@10% | EventualDet@30% |
|---|---|---|---|---|
| CS0-baseline | 0.0000 | 0.6164 | 0/3 | 3/3 |
| CSw1-window90 | 0.0000 | 0.8515 | 0/3 | 3/3 |
| CSw2-window90-ips16 | 0.2304 | 0.8515 | 2/3 | 3/3 |
| CSw3-window90-ips16-attempts24 | 0.2453 | 0.8578 | 2/3 | 3/3 |
| CSw4-conservative | 0.0948 | 0.8515 | 2/3 | 3/3 |

A 30%, las tres campañas ya se detectaban con el baseline
(`EventualDet@30%=3/3` en los 5 candidatos) — lo que gana `Window=90m`
ahí es que el gate queda disparado durante una fracción MUCHO mayor
de la campaña (`RecallDetector@30%` sube de 0.62 a ~0.85), no que
detecte campañas que antes se le escapaban del todo.

**Ningún candidato llega a 3/3 a 10%.** `CSw1` (solo ventana) se
queda en 0/3, igual que el baseline — confirma lo anticipado: la
ventana sola no alcanza. `CSw2`/`CSw3`/`CSw4` llegan a 2/3 (seeds 102
y 103), pero **el seed 101 sigue sin detectarse en NINGÚN candidato**,
incluido `CSw3`, pese a que sus umbrales (`MinDistinctIPs=16`,
`MinAttempts=24`) coinciden EXACTAMENTE con los máximos observados
para el seed 101 a `Window=90m` (16 y 24 respectivamente, ver
diagnóstico anterior).

**Por qué — un matiz importante que el diagnóstico anterior no
capturaba:** el máximo histórico de cada señal (`MaxWindowDistinctIPs`,
`MaxWindowTotalAttempts`, etc.) se mide de forma INDEPENDIENTE a lo
largo de la campaña — el máximo de IPs y el máximo de Attempts pueden
ocurrir en evaluaciones DISTINTAS, no necesariamente en el mismo
instante. El gate de credential_stuffing exige que las CUATRO
condiciones se cumplan SIMULTÁNEAMENTE en la misma evaluación. Para
el seed 101, el momento en que `DistinctIPs` llega a su máximo (16) no
es el mismo momento en que `TotalAttempts` llega al suyo (24) — así
que ninguna combinación de umbrales iguales a "el máximo de cada uno"
garantiza que el gate cruce. Esto no invalida el enfoque (los
candidatos SÍ mejoraron la detección en 2 de 3 seeds), pero corrige la
expectativa: "usar el mínimo de los máximos observados" es una cota
optimista, no una garantía, porque asume implícitamente que las
señales co-ocurren.

### Resultado — atribución por evento credential_stuffing (pooled entre seeds)

| Candidato | Ratio | Credential only | Anomaly only | Both | Neither |
|---|---|---|---|---|---|
| CS0-baseline | 10% | 0.0% | 95.3% | 0.0% | 4.7% |
| CSw1-window90 | 10% | 0.0% | 95.3% | 0.0% | 4.7% |
| CSw2-window90-ips16 | 10% | 0.0% | 71.1% | 24.2% | 4.7% |
| CSw3-window90-ips16-attempts24 | 10% | 0.0% | 69.5% | 25.8% | 4.7% |
| CSw4-conservative | 10% | 0.0% | 85.2% | 10.2% | 4.7% |
| CS0-baseline | 30% | 0.0% | 34.8% | 62.1% | 3.1% |
| CSw1-window90 | 30% | 0.0% | 11.7% | 85.2% | 3.1% |
| CSw2/CSw3/CSw4 | 30% | 0.0% | ~11.0-11.7% | ~85.2-85.8% | 3.1% |

`Credential only` sigue en 0.0% en los 5 candidatos, en los dos
ratios: credential_stuffing nunca termina de "ganar solo" — pero la
categoría `Both` sube muchísimo con `Window=90m` (30%: 62%→85%; 10%:
0%→24-26% en CSw2/CSw3), confirmando que el gate SÍ empieza a
disparar de forma mucho más consistente, solo que casi siempre en
paralelo con `statistical_anomaly`, nunca en soledad.

### Comparación explícita: cobertura vs. FPR vs. detection delay

- **FPR@0%**: idéntico en los 5 (con la salvedad de dataset ya
  señalada) — este sweep, tal como está, no distingue a los
  candidatos por este eje.
- **Cobertura (recall + detección eventual)**: `CSw3` es
  consistentemente el mejor o empatado con el mejor en cada métrica
  de cobertura medida (`RecallDetector@10/30`, `StrictRecall@30`),
  pero por márgenes pequeños sobre `CSw2`/`CSw4` — y ninguno resuelve
  el seed 101 a 10%.
  `CSw4` (el "conservador", sin tocar `MinAttempts`) logra
  prácticamente la misma detección eventual (2/3 a 10%) que
  `CSw2`/`CSw3`, con umbrales menos agresivos en `MinDistinctIPs`
  (18 en vez de 16).
- **Detection delay**: `CSw3` detecta ligeramente más rápido que
  `CSw2`/`CSw4` en los seeds que sí detecta a 10% (request 23-25 vs.
  24-26), una diferencia marginal, no dramática.
- **Riesgo/agresividad**: `CSw3` es el más agresivo (dos umbrales
  bajados al mínimo observado, sin margen); `CSw4` es el más
  conservador de los que sí mejoran algo (una sola reducción,
  moderada); `CSw2` queda en el medio.

No se seleccionó ningún candidato automáticamente. `S3`, `A3`,
`ScoreFloor`, `ChallengeThreshold`, `BlockThreshold` sin tocar. No se
usó holdout. Se espera tu comparación y aprobación antes de congelar
cualquier configuración de credential_stuffing.

## 2026-09-28 — Detector layer congelada en D1; sweep de Policy (tarea 1.9)

Se aprobó CSw2 (Window=90m, MinDistinctIPs=16, resto sin cambios) y
se congeló la detector layer completa para el resto del tuning:
credential_stuffing CSw2, slow_scan S3, statistical_anomaly A3. A
partir de acá, S3/A3/CSw2 no se vuelven a tocar durante la
calibración de Policy — solo se calibra `ChallengeThreshold`/
`BlockThreshold`, dejando `ScoreFloor` sin cambios, "porque Policy
está downstream de los detectores y se quiere aislar su efecto antes
de alterar la escala de RiskScore".

### Optimización de arquitectura: reaplicar Policy sin re-correr detectores

Como `principal.RiskScore`/`AttackVector` (lo que termina en
`Decision.ConfidenceScore`/`AttackVector`) NO depende de
`ChallengeThreshold`/`BlockThreshold` — según
`engine.BehavioralDecider.Decide`, la Policy solo decide la Action a
partir de un RiskScore ya calculado — se agregó
`engine.Policy.ActionFor` (wrapper exportado de la regla privada
`actionFor`, mismo criterio que `eval.Policy.IsPositive`) y
`internal/tuning.ReapplyPolicy`/`RunResultWithPolicy`: reaplican
Policy sobre decisiones YA calculadas por D1, sin volver a construir
ni correr ningún detector. Verificado con un test de equivalencia
explícito (`TestRunResultWithPolicy_SamePolicy_MatchesFullRun`):
reaplicar la MISMA Policy que produjo las decisiones originales da
`Eval`/`Delay` bit-a-bit idénticos a una corrida completa —
garantiza que la optimización no cambia ningún resultado. Válido
para cualquier `ChallengeThreshold > 0` (los 9 candidatos del sweep
lo son). Se agregó también `internal/tuning.ActionDistribution`
(legit/malicious x ALLOW/CHALLENGE/BLOCK, `FalseChallengeRate`,
`FalseBlockRate`) y el recall STRICT por vector (`strictByAttackVector`,
ya que `eval.Evaluate` solo expone `ByAttackVector` en broad).
Cubierto por 9 tests nuevos. `cmd/sweeppolicy` corrió el sweep real
en <1s (confirmando que no re-corrió ningún detector 9 veces) y
escribió `reports/tuning/sweep-policy.md`. Suite completa
(`gofmt`/`go vet`/`go test`/`go test -race`) en verde antes y
después.

### El sweep: 9 combinaciones, Challenge ∈ {0.50,0.55,0.60}, Block ∈ {0.70,0.75,0.80}

Las 9 combinaciones sobreviven el filtro Challenge<Block (el máximo
Challenge, 0.60, ya es menor que el mínimo Block, 0.70).

**Hallazgo estructural central: `FalseBlockRate` es 0.0000 en los 9
candidatos, en los tres ratios, sin excepción.** Con la detector
layer D1 y `ScoreFloor` actuales, el RiskScore de tráfico LEGÍTIMO
nunca cruza ningún `BlockThreshold` del grid — consistente con la
distribución de RiskScore ya documentada (statistical_anomaly legit
p95≈0.46, muy por debajo de 0.70). Esto simplifica la lectura del
sweep: en este dataset, elegir `BlockThreshold` no tiene NINGÚN
costo observado sobre usuarios legítimos — solo decide qué tan
agresivamente se trata al tráfico malicioso ya detectado (BLOCK vs
CHALLENGE), nunca si se bloquea a alguien real.

**Segundo hallazgo estructural: las métricas Broad (Precision/Recall/
FPR/FNR/F1/FalseChallengeRate) son IDÉNTICAS entre los 3 valores de
`BlockThreshold`, para un mismo `ChallengeThreshold`.** Es matemático:
Broad cuenta CHALLENGE y BLOCK como la misma "predicción positiva",
así que mover la frontera entre CHALLENGE y BLOCK nunca cambia si un
evento es positivo en términos Broad — solo cambia QUÉ acción
específica recibe. Solo `BlockThreshold` afecta: `StrictRecall`
(BLOCK puro), la atribución de `AttackVectorRecall` strict, y el
reparto `MaliciousChallenge` vs `MaliciousBlock` en la distribución
de acciones.

| ChallengeThreshold | FPR@0% | Precision@10% | Recall@10% | F1@10% | Precision@30% | Recall@30% | F1@30% |
|---|---|---|---|---|---|---|---|
| 0.50 | 0.0381 | 0.7697 | 0.9203 | 0.8383 | 0.9460 | 0.7559 | 0.8403 |
| 0.55 | 0.0195 | 0.8380 | 0.7246 | 0.7772 | 0.9617 | 0.6208 | 0.7545 |
| 0.60 | 0.0086 | 0.8889 | 0.5604 | 0.6874 | 0.9751 | 0.5707 | 0.7200 |

Subir `ChallengeThreshold` reduce el FPR de forma monótona (bueno)
pero también reduce Recall/F1 de forma pronunciada (0.50→0.60 casi
divide a la mitad el recall a 10% y 30%).

**Tercer hallazgo, no buscado: `CS Strict recall = 0.0000` en los 9
candidatos**, pese a que el RiskScore de credential_stuffing sobre
tráfico malicioso (D1, ver sección anterior) tiene p50=0.77 y
p90=0.84 — muy por encima de cualquier `BlockThreshold` del grid.
La explicación: cuando credential_stuffing dispara junto con
`statistical_anomaly` (el caso casi universal, ver
"WithAnomalyAssist" de la sección anterior), el RiskScore de
`statistical_anomaly` para ese mismo evento resulta ser mayor (o
empata sin favorecer a credential_stuffing en la práctica), así que
`statistical_anomaly` gana como Finding principal y
`Decision.AttackVector` queda atribuido a `statistical_anomaly`, no a
`credential_stuffing` — la Policy nunca puede "ver" a
credential_stuffing como vector ganador en este dataset, sin importar
dónde se pongan los umbrales. Esto no es un problema de Policy: es
una consecuencia de cómo `selectPrincipal` desempata por score, y
queda documentado como una limitación conocida para una futura
revisión (fuera del alcance actual, que es solo calibrar
`ChallengeThreshold`/`BlockThreshold`).

**Estabilidad entre seeds**: el Range (max-min entre los 3 seeds) de
BroadRecall a 30% baja de 0.316 (Challenge=0.50) a 0.266 (0.55) a
0.153 (0.60) — subir Challenge no solo baja el recall, también lo
hace más estable entre seeds, a costa de perder cobertura.

### Tres opciones propuestas, con trade-offs claramente distintos — ninguna seleccionada

| Opción | Config | Perfil |
|---|---|---|
| **A — Cobertura primero** | Challenge=0.50, Block=0.70 (o 0.75/0.80, Broad idéntico) | Mejor Recall/F1 (0.92/0.76, F1≈0.84), pero mayor FPR (0.033-0.038) y la mayor inestabilidad entre seeds (Range 0.32 @30%). FalseChallengeRate 2.0-3.8%. |
| **B — Balanceada** | Challenge=0.55, Block=0.70-0.80 | FPR bastante más bajo (0.011-0.020), Precision alta (0.84-0.96), pero Recall/F1 caen sensiblemente (0.72/0.62, F1≈0.75-0.78). Estabilidad intermedia (Range 0.27 @30%). |
| **C — Precisión/mínima fricción** | Challenge=0.60, Block=0.70-0.80 | El FPR y FalseChallengeRate más bajos del grid (0.007-0.009), mejor Precision (0.89-0.98), pero Recall se derrumba más (0.56/0.57, F1≈0.69-0.72). La más estable entre seeds (Range 0.15 @30%). |

Dentro de cada opción, `BlockThreshold` (0.70/0.75/0.80) no cambia
ninguna métrica Broad ni `FalseBlockRate` (siempre 0) — solo decide
qué fracción del tráfico malicioso ya mitigado recibe BLOCK directo
en vez de CHALLENGE (`StrictRecall` sube de ~0.26 a ~0.47-0.49 al
bajar Block de 0.80 a 0.70, dentro de cualquier opción).

No se seleccionó ningún candidato por F1 máximo ni por BLOCK recall
máximo — la elección queda pendiente de aprobación. `ScoreFloor` sin
tocar. No se usó holdout. Reporte completo con las 9 combinaciones x
3 seeds x 3 ratios en `reports/tuning/sweep-policy.md`. Se detiene
acá, después del sweep, según lo pedido.

## 2026-09-28 — Policy aprobada; corrección de attribution; configuración congelada pre-holdout (tarea 1.9)

### Policy final aprobada

`ChallengeThreshold=0.50`, `BlockThreshold=0.75`. Justificación dada
explícitamente: subir Challenge a 0.55/0.60 reduce FPR pero sacrifica
demasiado Broad recall; Block=0.80 es demasiado conservador respecto
a los RiskScores maliciosos observados; Block=0.70 es más agresivo y
el dataset legítimo de tuning no estresa suficientemente todos los
patrones benignos como para confiar en el margen; 0.75 es el punto
intermedio. `FalseBlockRate` fue 0 en las 9 combinaciones del grid,
pero **eso es una propiedad de estos datasets de tuning, no una
garantía general** — no se debe asumir que se mantendrá igual contra
tráfico real o incluso contra holdout.

### Corrección de una limitación semántica de attribution (sin tocar detección, RiskScore ni Policy Action)

Se detectó que `statistical_anomaly`, al tener a veces el mayor
RiskScore, podía convertirse en principal y dejar
`attack_vector=unknown` en la Decision aunque `credential_stuffing` o
`slow_scan` también hubieran disparado — una attribution engañosa:
"no sabemos qué es esto" cuando sí había una hipótesis específica
activa.

**Regla de attribution nueva** (`internal/engine/behavioral.go`): se
separan dos preguntas que antes resolvía el mismo Finding:

1. **Action/ConfidenceScore** ("qué tan riesgoso es"): sigue siendo
   el mayor RiskScore entre TODOS los Triggered, sin importar qué
   detector lo produjo — `selectPrincipal`, sin cambios de lógica
   (solo refactorizado para compartir el desempate con
   `selectAttribution` vía el helper `bestIndexByScore`).
2. **AttackVector/EntityID/ContributingSignals/Explanation
   principal** ("de qué ataque se trata"): si CUALQUIER detector
   ESPECÍFICO (`credential_stuffing`/`slow_scan`) disparó, se usa el
   de mayor RiskScore ENTRE ESOS — `statistical_anomaly` nunca es
   candidato en ese caso, sin importar cuánto mayor sea su propio
   score. Solo cuando NINGÚN específico disparó se usa
   `statistical_anomaly` (que ya reporta `unknown` como su propio
   AttackVector, no una regla especial de esta función) —
   `selectAttribution`.

El desempate determinista entre detectores específicos (credential_stuffing
gana un empate exacto contra slow_scan) se mantiene sin cambios,
ahora factorizado en `bestIndexByScore` y reutilizado por las dos
funciones. `explanationFor` pasó a recibir `decisionScore` por
separado del Finding atribuido, y el texto dice "decision score" en
vez de "risk score" para no insinuar que ese número es el RiskScore
propio de la evidencia descrita — y ya no afirma "but scored lower"
sobre los secondaries (podía ser falso: un secondary puede tener
score mayor y perder igual por no ser específico).

**Tests nuevos** (`internal/engine/behavioral_test.go`): 5 tests
unitarios puros sobre `selectAttribution`/`bestIndexByScore` con
`triggeredFinding` sintéticos (específico gana con score menor;
ambos específicos, gana el mayor score; empate exacto respeta la
prioridad; solo anomaly da `unknown`; vacío da `nil`), más un test de
integración de extremo a extremo con detectores reales
(`TestDecide_AttributionPrefersSpecific_ButConfidenceScoreStaysMax`):
credential_stuffing dispara a su ScoreFloor (0.2, mismo escenario ya
verificado en un test anterior) mientras `statistical_anomaly`, con
el baseline global ya calentado, dispara con un score claramente
mayor para la misma IP — confirma que `AttackVector`/`EntityID` quedan
en `credential_stuffing` mientras `ConfidenceScore` sigue siendo el
score MÁS ALTO (mayor al 0.2 de referencia), nunca el propio de
credential_stuffing. Los 20 tests preexistentes de
`internal/engine` pasan sin ningún cambio — incluido
`TestDecide_AnomalyFindingCanBePrincipal_WhenHigherScore` (sigue
dando `unknown`, porque ahí NINGÚN detector específico dispara nunca,
por construcción) y `TestDecide_OtherDetectorStaysPrincipal_OverAnomaly`
(sigue dando `slow_scan`, ahora por una razón estructuralmente más
fuerte: es el único específico disparado, ya no depende de que su
score sea mayor).

### Verificación empírica: re-corrida de tuning, resultado idéntico

Se re-corrió `cmd/sweeppolicy` (detector layer D1 + los 9 candidatos
de Policy, tuning completo) con el código YA corregido, y se comparó
el reporte resultante contra una copia guardada de ANTES del cambio
de attribution: **`diff` entre ambos reportes fue completamente
vacío** — cero diferencias en absolutamente ningún número, incluidos
`TP/FP/TN/FN`, `Precision`, `Recall`, `FPR`, `FNR`, `F1` (broad y
strict), la distribución de Action, y hasta el recall por vector
(`CS Broad/Strict`, `SlowScan Broad/Strict`). Esto confirma la
equivalencia pedida: la corrección de attribution no cambió ninguna
métrica de acción.

**Corrección a una afirmación anterior**: en el resumen del sweep de
Policy se dijo "CS Strict recall = 0.0000 en los 9 candidatos" sin
matizar — la re-lectura del reporte muestra que eso solo es exacto a
**10%** (muestra chica, genuinamente 0 ahí); a **30%** `CS Strict
recall` ya era sustancial (0.57-0.74) ANTES de este cambio también.
La explicación correcta: la RiskScore mediana de credential_stuffing
sobre tráfico malicioso (~0.77) ya solía ser más alta que la de
statistical_anomaly (~0.50) en los eventos donde ambos coinciden, así
que credential_stuffing YA ganaba el desempate por score en la
mayoría de esos casos, incluso con la regla anterior — por eso la
corrección de attribution no cambió nada medible en este dataset
específico: no es que el cambio no funcione, es que en este dataset
concreto casi nunca se daba la condición (anomaly con score
mayor) que el cambio corrige. El test de integración nuevo prueba
explícitamente que si esa condición SÍ se da, la corrección actúa
como se espera.

### Configuración final congelada, pre-holdout

**Detector config final:**

| Detector | Parámetro | Valor |
|---|---|---|
| credential_stuffing (CSw2) | Window | 90 min |
| | MinDistinctIPs | 16 |
| | MinDistinctAccounts | 15 (sin cambios) |
| | MinAttempts | 25 (sin cambios) |
| | MinFailedRatio | 0.60 (sin cambios) |
| slow_scan (S3) | MaxVisitorsForNovelPath | 3 |
| | MinNovelPathRatio | 0.35 |
| statistical_anomaly (A3) | AccountDiversityWeight | 0.5 |
| | resto | default (`engine.DefaultAnomalyConfig()`) |

**Policy final:** `ChallengeThreshold=0.50`, `BlockThreshold=0.75`.

**ScoreFloor:** sin cambios en los tres detectores (el de cada
`Default*Config()` — nunca se tocó en ningún paso de la tarea 1.9).

**Regla de attribution** (código, no threshold): un detector
específico (`credential_stuffing`/`slow_scan`) Triggered siempre gana
la attribution de `AttackVector`/`EntityID`/`ContributingSignals`
sobre `statistical_anomaly`, sin importar el RiskScore relativo;
`Action`/`ConfidenceScore` siguen viniendo del mayor RiskScore entre
todos los Triggered, sin cambios.

**Limitaciones conocidas, documentadas explícitamente:**

- El dataset de 0% no genera tráfico legítimo de alto volumen desde
  un mismo ASN/patrón de login — `FalseBlockRate=0` y la
  insensibilidad de `FPR@0%` a los umbrales de credential_stuffing
  observadas en el tuning NO deben leerse como garantía contra
  tráfico legítimo real de ese tipo.
- `MinDistinctIPs=16`/`Window=90m` de CSw2 se derivaron de los
  máximos observados en solo 3 seeds de tuning — sin margen de
  sobra, candidato deliberadamente ajustado a ese dataset concreto.
- La regla de attribution nueva no fue estresada contra ningún caso
  donde el score de statistical_anomaly sea mayor en el dataset de
  tuning real (según el punto anterior, esa condición casi no se dio
  ahí) — su corrección está probada por el test de integración
  sintético, no por un cambio medible en las métricas de tuning.

No se ejecutó holdout todavía. El siguiente paso es crear el
checkpoint/commit pre-holdout y recién después correr holdout (seeds
201/202/203) con esta configuración congelada.

## 2026-09-28 — Holdout final: Baseline vs. Final Tuned Config (tarea 1.9)

Checkpoint pre-holdout ya creado (commit `6abed47`). Con la
configuración completamente congelada, se corrió holdout por
**primera y única vez**: seeds 201/202/203, ratios 0/10/30%,
comparando BASELINE ORIGINAL (sin ningún cambio) contra FINAL TUNED
CONFIG (credential_stuffing CSw2, slow_scan S3, statistical_anomaly
A3, Policy Challenge=0.50/Block=0.75, ScoreFloor sin tocar) — y,
para medir generalización, la MISMA comparación recalculada también
sobre tuning (seeds 101/102/103) con exactamente esta configuración
final (no reutilizando números de reportes previos con otra Policy).

### Infraestructura nueva

Se refactorizó `RenderDetectorLayerComparison` (sin cambiar su
salida más que un título cosmético, verificado con `diff` contra el
reporte anterior) para extraer `renderDetectorLayerCandidateSection`
y `renderDetectorLayerSideBySide`, reutilizables con cualquier par de
reportes, no solo D0/D1. `internal/tuning/holdout_report.go`:
`DetectorLayerStability`/`ComputeDetectorLayerStability` (Range entre
seeds de BroadRecall/StrictRecall/FPR/CS y SlowScan RecallDetector),
`HoldoutDatasetReport`, `RenderHoldoutReport`. `cmd/holdout` corre
Baseline y Final sobre tuning Y holdout (4 corridas completas) y
escribe `reports/holdout/baseline-vs-final.md`. 2 tests nuevos.
Suite completa en verde antes y después.

### Resultado — Baseline vs. Final, dentro de holdout (pooled 3 seeds)

| Ratio | Métrica | Baseline | Final |
|---|---|---|---|
| 0% | FPR (broad) | 0.0529 | 0.0617 |
| 10% | Precision / Recall / F1 (broad) | 0.7116 / 0.8479 / 0.7738 | 0.7182 / 0.9549 / 0.8198 |
| 10% | Recall (strict/BLOCK) | 0.0535 | 0.2648 |
| 30% | Precision / Recall / F1 (broad) | 0.9468 / 0.4842 / 0.6407 | 0.9621 / 0.8837 / 0.9213 |
| 30% | Recall (strict/BLOCK) | 0.0070 | 0.3578 |
| 10%/30% | CS RecallDetector | 0.0000 / 0.6060 | 0.1148 / 0.8517 |
| 10%/30% | SlowScan RecallDetector | 0.6298 / 0.1494 | 0.6298 / 0.5577 |

Final sigue superando a Baseline en holdout en prácticamente todas
las métricas de cobertura — el patrón observado en tuning se
reproduce.

### Hallazgo central, no visto en tuning: 3 falsos BLOCK reales en holdout (FalseBlockRate ya no es 0)

En tuning, `FalseBlockRate` fue exactamente 0.0000 en los 9
candidatos del sweep de Policy — se documentó explícitamente como
"propiedad de estos datasets de tuning, no garantía general" (ver
sección anterior). **En holdout, esa garantía se rompe**: el
candidato Final tuvo **3 eventos legítimos bloqueados de verdad** a
0% (seed 203), `FalseBlockRate=0.0008` (3 de 3628) — chico, pero
real y distinto de cero por primera vez en toda la tarea 1.9.

**Causa identificada explícitamente, no por eliminación**: la
distribución de RiskScore de `statistical_anomaly` sobre tráfico
LEGÍTIMO tiene un máximo de **0.7722** en holdout (Final), por
encima de `BlockThreshold=0.75` — mientras que en tuning ese máximo
nunca superó 0.6998-0.7079. `credential_stuffing` y `slow_scan`
siguen en 0.0000 de máximo sobre tráfico legítimo en holdout
también (confirmado en la tabla de RiskScore) — los falsos BLOCK
NO vienen de los detectores específicos ni de CSw2, vienen
enteramente de `statistical_anomaly`, cuyo baseline GLOBAL
ocasionalmente ve una sesión legítima lo bastante inusual (dentro de
~10884 eventos legítimos de holdout) como para cruzar el umbral —
un efecto estadístico esperable a esa escala con un baseline global,
no un error de configuración. Coincide exactamente con la
limitación ya documentada "el baseline anomaly es global".

También se invirtió el signo de la comparación Baseline-vs-Final en
`FPR@0%`: en tuning, Final tenía FPR menor que Baseline (0.0381 vs.
0.0469); en holdout, Final tiene FPR **mayor** (0.0617 vs. 0.0529).
Ambos FPR siguen siendo bajos en términos absolutos, pero es una
señal real de que la mejora de FPR@0% observada en tuning no
generalizó en la misma dirección.

### Generalización: tuning vs. holdout, candidato Final

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

**Lectura general**: la mayoría de las métricas de cobertura (Broad
Recall, F1, SlowScan RecallDetector, CS RecallDetector@30%)
generalizan bien o incluso mejoran en holdout — sin señal de
overfitting ahí. La señal de generalización más débil está
concentrada en dos lugares concretos, ambos coherentes con
limitaciones ya documentadas antes de correr holdout: **CS
RecallDetector@10%** (cae a la mitad — CSw2 se calibró con el margen
justo de solo 3 tuning seeds, sin margen de sobra) y **FPR@0%/los 3
falsos BLOCK** (statistical_anomaly, baseline global, efecto de
escala). Ninguna de las dos es una sorpresa cualitativa — son
exactamente los dos riesgos que se habían anticipado y documentado
como limitaciones antes de ver estos resultados.

### Estabilidad entre seeds

En holdout, Final es MÁS estable que en tuning para BroadRecall
(Range 0.030-0.079 vs. 0.113-0.316 en tuning) y para FPRBroad
(0.035-0.074 vs. 0.039-0.044) — pero MENOS estable para StrictRecall
a 10% (Range 0.349 en holdout vs. 0.050 en tuning): los 3 seeds de
holdout difieren bastante entre sí en cuánto tráfico llega a BLOCK
puro a 10%, aunque coincidan mucho más en Broad Recall. Detalle
completo por seed en `reports/holdout/baseline-vs-final.md`.

### Limitaciones documentadas, confirmadas con evidencia de holdout

- **Dataset 0% sin tráfico legítimo de login de alto volumen/mismo
  ASN**: sigue sin resolverse — `credential_stuffing` nunca disparó
  sobre tráfico legítimo en holdout tampoco (máximo de RiskScore
  legit = 0.0000, igual que en tuning). Esta limitación NO fue la
  causa de los 3 falsos BLOCK — fue `statistical_anomaly`.
- **CSw2 calibrado con solo 3 tuning seeds**: confirmado con datos
  reales — `CS RecallDetector@10%` cae de 0.23 a 0.11 en holdout,
  la señal de generalización más débil de todo el reporte.
- **Detectores/features stateful**: cada corrida (tuning y holdout)
  parte de estado limpio por diseño (`Candidate.Build`), así que la
  comparación es justa — pero en producción real el estado persiste
  indefinidamente, algo que ningún holdout de este tipo puede medir.
- **El baseline de `statistical_anomaly` es global**: confirmado como
  causa directa de los 3 falsos BLOCK en holdout — un baseline
  compartido entre todas las entidades puede, a cierta escala, ver a
  una entidad legítima como estadísticamente extrema por azar. No es
  un bug: es la limitación conocida de diseño manifestándose con
  datos reales por primera vez.

### No se propuso ningún threshold nuevo

Tal como se pidió explícitamente, no se modificó ningún parámetro en
función de estos resultados, aunque el holdout mostrara puntos
peores que tuning (FPR@0%, StrictRecall@10%, CS RecallDetector@10%).
Detector config, Policy y ScoreFloor permanecen exactamente como se
congelaron en el checkpoint pre-holdout. Reporte completo, por seed
y agregado, en `reports/holdout/baseline-vs-final.md`. Se detiene
acá — no se avanza todavía a performance/load.
