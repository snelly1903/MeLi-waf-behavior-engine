# Decisiones técnicas

Este documento describe las decisiones de arquitectura y diseño del motor de
detección conductual (`waf-behavior-engine`), organizadas por tema: qué
problema resolvía cada decisión, qué se eligió, por qué, qué trade-off se
aceptó y qué limitaciones quedan documentadas.

## 1. Arquitectura general

### Separación estructural del ground truth

**Problema.** El motor de detección nunca debe poder "ver" la etiqueta real
(`legit`/`credential_stuffing`/`slow_scan`) de un evento — cualquier
medición de su desempeño quedaría contaminada si pudiera.

**Decisión.** `internal/groundtruth` contiene las etiquetas. Ninguna parte
del motor (`cmd/engine`, `internal/engine`, `internal/httpapi`, los
detectores) importa ese paquete — la dependencia va en un solo sentido.
`internal/eval` e `internal/datagen` son los únicos paquetes que sí lo
importan: la regla nunca fue "nadie puede verlo", fue "el motor nunca lo
ve".

**Motivo.** Verificado con tests, no solo con disciplina al escribir
código: un test por reflexión sobre `Event` falla si aparece un campo con
nombre parecido a `label`/`truth`/`attack_type`, y un test sobre el JSON
serializado confirma que esas palabras tampoco viajan por la red (detalle
en la sección 2).

**Limitación.** Es una garantía sobre el *contrato* del evento, no una
prueba formal de que ninguna futura línea de código pueda filtrar la
etiqueta por otro camino (por ejemplo, un campo de texto libre mal usado).

### `cmd/engine` y `BehavioralDecider`

**Decisión.** Un servicio HTTP (`POST /v1/events`) valida con
`event.Validator` y le pasa el evento a un `engine.Decider`
(`Decide(ctx, event.Event) decision.Decision`). La implementación real,
`BehavioralDecider`, alimenta a los tres detectores con cada evento
(`Observe` en todos, después `Evaluate` en todos — el orden entre
detectores no importa porque no comparten estado, pero `Observe` antes que
`Evaluate` para el mismo evento sí es parte del contrato de cada uno),
selecciona el `Finding` principal y aplica `Policy` (sección 8).

**El `RiskScore` final es el máximo entre los `Finding` disparados, nunca
la suma ni el promedio** — cada detector mide algo distinto con su propia
escala heurística; sumarlos habría inventado un número sin significado.

**Generalización a N detectores.** Una interfaz privada `detector`
(`Observe`/`Evaluate`/`Sweep`), definida donde se consume — los tres
detectores ya la cumplían sin tocarles ninguna firma. El constructor sigue
recibiendo los tres detectores como parámetros explícitos y tipados (no una
lista genérica), para que el sitio de construcción quede legible.
Prioridad de desempate fija: `credential_stuffing(0) > slow_scan(1) >
statistical_anomaly(2)` — el más específico gana un empate exacto de
score; el genérico es el último recurso.

**Credential stuffing sin ASN real por defecto:
`credstuffing.UnavailableNetworkResolver`** — un tipo de producción (no un
fake de test) cuyo `Resolve` siempre devuelve `ok=false`, así que ninguna
IP entra a ninguna correlación pero el detector corre de verdad. Se
prefirió sobre un detector nulable (obliga a checks de `nil` en cada punto
de uso) o reutilizar el fake de los tests (no debe llegar a producción).

**Concurrencia.** `BehavioralDecider` no agrega estado mutable propio —
solo punteros a detectores (ya seguros por diseño propio) y un `Policy`
(value type inmutable). Confirmado con `go test -race`.

### `internal/wiring`: única fuente de verdad de la configuración final

**Problema.** El load test (sección 11) necesitaba medir la configuración
final calibrada (secciones 4, 5, 6 y 8), mientras `cmd/engine` seguía
sirviendo su configuración *por defecto, sin calibrar* — una brecha real
entre lo que el motor decía servir y lo que se había validado.

**Decisión.** `internal/wiring.FinalConfigs()`/`FinalPolicy()` son la
única fuente de verdad de la configuración runtime final; tanto
`cmd/engine` como `cmd/loadtest` la consumen desde ahí, para que nunca
puedan divergir silenciosamente. La configuración baseline original (sin
calibrar) sigue viviendo exclusivamente en sus funciones de default,
usada solo por la infraestructura de comparación baseline-vs-final del
tuning. No fue un retuning: ningún valor cambió, solo se cerró la brecha
de wiring. `internal/wiring` nunca importa `internal/datagen` — el
resolver de ASN ya construido se pasa como parámetro, quien llama decide
de dónde sale.

## 2. Validación de eventos

**Problema.** Necesitábamos un contrato mínimo y verificable para el
evento HTTP, sin acoplar la validación a ninguna aplicación protegida
concreta.

**Decisión.** 6 campos obligatorios (`request_id`, `timestamp`,
`client_ip`, `method`, `path`, `status_code`) — el mínimo que cualquier
fuente de logs real puede ofrecer, suficiente para construir las señales
de ambos ataques. `event.Validator` valida rango de fecha, IP pública,
forma del método y tamaño de `path`, y devuelve **todos** los errores a
la vez, no solo el primero.

**Por qué el método HTTP no está restringido a la lista clásica.** Un
método raro (`TRACE`, o inventado por fuzzing) puede ser en sí mismo una
señal de escaneo — si la validación lo rechazara de entrada, el detector
nunca llegaría a verlo. Solo se valida que sea sintácticamente válido
según RFC 7230 §3.2.6.

**Privacidad por diseño.** `login_user_hash` es una huella (HMAC, no
reversible) del usuario intentado, nunca el email en claro;
`query_params` guarda solo nombres de parámetro, nunca valores; no existe
ningún campo para el cuerpo del request. Verificado con tests que
inspeccionan el JSON serializado buscando `password`/`token`/`cookie`.

**Timestamps: dos mecanismos distintos, no confundir.** La validación de
rango (`MaxPastAge`/`MaxFutureSkew`) es higiene de datos, corre una sola
vez al entrar el evento. El watermark de las ventanas de los detectores
(sección 3) decide algo distinto — a qué bloque de tiempo pertenece un
evento que puede llegar desordenado — y corre después, dentro del motor.

**`internal/httpapi`** decodifica JSON, normaliza y valida con
`event.Validator` (reutilizado tal cual, sin duplicar ninguna regla), y le
pasa el evento ya validado al `Decider` — no sabe nada de cómo se toma una
decisión.

**Garantías estructurales de aislamiento del ground truth** — ver sección 1.

## 3. Perfiles temporales y ventanas

**Problema.** Los tres detectores necesitan una noción de "comportamiento
reciente" por entidad (IP, sesión, grupo de red), sin guardar historial
sin límite y sin que un evento tardío rompa la ventana ya cerrada.

**Decisión — `internal/profile`.** Componente con estado, en memoria (map
+ slice, protegido con mutex), que guarda observaciones por entidad dentro
de una ventana deslizante configurable. Es el componente con estado que
comparten `internal/credstuffing`, `internal/slowscan` e
`internal/anomaly` (cada uno con su propia instancia/ventana).

**El mecanismo de watermark.** Cada entidad guarda su propio watermark: el
timestamp más reciente ya observado para esa entidad. Un evento nuevo con
timestamp posterior al watermark lo adelanta y dispara la purga de
observaciones fuera de ventana; un evento con timestamp *anterior* al
watermark (llegó desordenado) se agrega igual dentro de la ventana, sin
purgar nada — nunca se descarta silenciosamente ni se rechaza como
inválido, solo se cuenta en una métrica separada. Este mecanismo se
reutiliza tal cual en los tres detectores.

**Por qué watermark por entidad y no un reloj global.** Entidades
distintas pueden estar en momentos distintos de su propia ventana al mismo
tiempo real (una IP activa hace 2 minutos, otra hace 2 horas) — un
watermark único global forzaría a purgar por la entidad más "adelantada",
rompiendo la ventana de todas las demás.

**Limpieza de memoria: dos mecanismos con propósitos distintos.** La purga
por watermark (arriba) libera observaciones fuera de ventana de una
entidad activa. `Sweep(now, idleTTL)`, en cambio, libera la entidad
completa cuando lleva más de `idleTTL` sin ninguna actividad — sin este
segundo mecanismo, una entidad que dejó de mandar tráfico (por ejemplo, un
atacante que se fue) quedaría ocupando memoria indefinidamente aunque su
ventana ya esté vacía.

**Concurrencia y copias defensivas.** Cada entidad tiene su propio lock;
`Snapshot` devuelve una copia, nunca un puntero al estado interno — un
detector puede leer un snapshot mientras otro goroutine sigue observando
la misma entidad, sin condición de carrera. Confirmado con `go test -race`.

**Qué se retiene por observación.** Solo lo que cada detector necesita
para su cálculo (timestamps, status codes, rutas, cuentas intentadas) —
nunca `login_user_hash` en claro más allá de lo que ya llega hasheado,
nunca `query_params` con valores (el contrato ya los excluye, sección 2).

## 4. Credential Stuffing

**Qué es y qué no es.** Correlaciona intentos de login **entre IPs del
mismo grupo de red (ASN)** dentro de una ventana deslizante — nunca por IP
individual, que es exactamente lo que un atacante distribuido evita.
Cuatro señales normalizadas se combinan en un gate conjuntivo: diversidad
de IPs distintas, diversidad de cuentas probadas, volumen de intentos,
ratio de fallos.

**El gate conjuntivo y el `ScoreFloor`.** Las cuatro señales tienen que
cruzar su propio umbral simultáneamente para que el detector dispare — sin
esto, una sola señal extrema (por ejemplo, muchísimos intentos desde una
sola IP conocida) podría disparar sin evidencia de distribución real.
`ScoreFloor` evita que un gate disparado justo en su umbral reporte riesgo
0 (un `Finding` disparado nunca puede tener `RiskScore=0`).

**Calibración.** Se calibró contra datasets de tuning (seeds 101-103),
separados del dataset de reporte. La configuración original (`Window=30
min`, `MinDistinctIPs=20`) casi nunca disparaba por sí sola en campañas al
10% de tráfico malicioso — dependía casi por completo de
`statistical_anomaly` como asistencia (sección 6), porque la ventana de 30
minutos era demasiado corta frente a las 3 horas en que se desarrolla una
campaña real. Un sweep de 5 candidatos (variando `Window` entre 30/60/90
min y `MinDistinctIPs`/`MinAttempts`) confirmó que ensanchar la ventana
era la palanca principal; llevar los umbrales al mínimo exacto observado
no generalizaba mejor que un margen moderado. Se eligió `Window=90 min`
con `MinDistinctIPs=16` sobre una alternativa más conservadora
(`MinDistinctIPs=18`) por dar mejor cobertura sin llevar dos umbrales al
mínimo a la vez.

**`FPR@0%` fue idéntico entre los 5 candidatos evaluados — limitación del
dataset, no garantía.** El dataset sintético no tiene tráfico legítimo que
se parezca lo suficiente a credential stuffing (mismo ASN, mismo endpoint,
volumen alto) como para que bajar estos umbrales disparara ningún falso
positivo nuevo — esto no demuestra que sean seguros contra tráfico
legítimo real de ese tipo, solo que no rompen nada contra este generador
concreto.

**Configuración final congelada:**

| Parámetro | Valor |
|---|---|
| Window | 90 min |
| MinDistinctIPs | 16 |
| MinDistinctAccounts | 15 |
| MinAttempts | 25 |
| MinFailedRatio | 0.60 |
| ScoreFloor | sin cambios (nunca se tocó durante la calibración) |

**Resultado en holdout.** El recall propio del detector cae de 0.2304
(tuning) a 0.1148 (holdout) al 10% de tráfico malicioso — la señal de
generalización más débil de todo el proyecto, coherente con que estos
umbrales se derivaron de los máximos observados en solo 3 seeds de
tuning, sin margen de sobra. Al 30% generaliza casi perfecto (0.8515 →
0.8517). El máximo de `RiskScore` sobre tráfico legítimo se mantuvo en
0.0000 tanto en tuning como en holdout — los falsos BLOCK que sí
aparecieron en holdout (sección 8) no se originaron en este detector.

## 5. Slow Scan

**Qué es y qué no es.** Detecta enumeración/escaneo lento de rutas por IP
y/o por sesión — evaluando siempre las dos cuando existe sesión, porque un
atacante puede rotar de sesión manteniendo la misma IP, o viceversa; si
solo se evaluara una, perdería cobertura contra cualquiera de las dos
estrategias.

**Las señales del gate.** Ratio de `404`, diversidad/novedad de rutas
visitadas (contra la popularidad global de cada ruta, no un catálogo
externo — es la opción mínima técnicamente correcta dado lo que el motor
puede observar), y entropía de la secuencia de rutas. Mismo mecanismo de
piso (`ScoreFloor`) que credential stuffing, por la misma razón: en el
borde exacto del gate, las señales normalizadas darían componentes en 0.

**Calibración.** Igual que credential stuffing, contra tuning (seeds
101-103). El baseline original mostraba degradación clara del recall al
subir la proporción de tráfico malicioso (0.89 al 10%, cayendo a 0.25-0.44
al 30%) — un patrón inverso al de los otros dos detectores. Un sweep
combinado con `statistical_anomaly` (sección 10) mostró que ajustar
`MaxVisitorsForNovelPath` y `MinNovelPathRatio` recuperaba buena parte de
ese recall perdido (de 0.30 a 0.69 en `SlowScan RecallDetector@30%`) sin
costo medible en falsos positivos.

**Configuración final congelada:**

| Parámetro | Valor |
|---|---|
| MaxVisitorsForNovelPath | 3 |
| MinNovelPathRatio | 0.35 |
| Resto | sin cambios |
| ScoreFloor | sin cambios |

**Resultado en holdout.** El recall propio generaliza razonablemente bien
entre tuning y holdout (0.7045→0.6298 al 10%; 0.4758→0.5577 al 30%,
incluso mejor) — de los tres detectores, el que muestra el comportamiento
más estable entre tuning y holdout.

## 6. Detección estadística de anomalías

**Qué es y qué no es.** El único detector no basado en reglas fijas por
umbral crudo: mantiene un baseline estadístico global (media/varianza
online, algoritmo de Welford) sobre cinco features por entidad (ratio de
not-found, ratio de fallos de auth, diversidad de rutas, ausencia de
referer, diversidad de cuentas) y calcula z-scores unilaterales sobre ese
baseline. Un único umbral sobre el score combinado decide si dispara.

**Por qué las muestras que disparan NO actualizan el baseline.** Durante
el warm-up se agrega siempre (todavía no hay ningún juicio de "anómalo"
que hacer). Después del warm-up, una muestra que resultó `Triggered` no se
agrega — así una anomalía real nunca termina absorbida como si fuera parte
de lo normal (*baseline poisoning*). Si el tráfico ya es mayormente ataque
desde el arranque, esta protección no puede hacer nada por sí sola —
limitación conocida de cualquier baseline aprendido sin supervisión,
documentada, no resuelta acá.

**Calibración.** Los falsos positivos del baseline (41-76 por corrida al
0% de tráfico malicioso) resultaron, confirmado con datos y no solo por
eliminación, 100% atribuibles a este detector — los otros dos nunca
disparan sobre tráfico exclusivamente legítimo. El corte matemático
(`ScoreFloor=0.20`, `ChallengeThreshold=0.50` → combined≈0.375) se
confirmó casi exacto contra datos reales, lo que descartó
`TriggerThreshold` como palanca útil (estaba muy por debajo de ese punto).
Un sweep de 6 candidatos mostró que bajar `ZSaturation` reducía falsos
positivos con más fuerza, pero dañaba el recall de `credential_stuffing`
de forma severa e irregular entre seeds (hasta 0.34 en algún seed, por la
pérdida de cobertura que `statistical_anomaly` le presta a los otros dos
detectores). `AccountDiversityWeight=0.5` fue el único de los 6 candidatos
que **mejora** recall en vez de dañarlo (`BroadRecall@30%` de 0.494 a
0.672), con una reducción de falsos positivos más modesta pero sin ese
costo.

**Configuración final congelada:**

| Parámetro | Valor |
|---|---|
| AccountDiversityWeight | 0.5 |
| Resto | default |
| ScoreFloor | sin cambios |

**Regla de atribución: por qué `statistical_anomaly` deja de "ganar" el
vector.** Al tener a veces el mayor `RiskScore`, podía convertirse en
principal y dejar `attack_vector=unknown` aunque `credential_stuffing` o
`slow_scan` también hubieran disparado — una atribución engañosa ("no
sabemos qué es esto" cuando sí había una hipótesis específica activa). La
corrección separa dos preguntas independientes: **qué tan riesgosa** es
una decisión (`Action`/`ConfidenceScore` = el mayor `RiskScore` entre
todos los `Finding` disparados, sin cambios) de **de qué ataque se trata**
(`AttackVector`/`EntityID`/evidencia = siempre un detector específico si
alguno disparó, nunca `statistical_anomaly`, aunque tenga mayor score). Se
verificó con un test de equivalencia que `Action`/`ConfidenceScore` quedan
bit-a-bit idénticos antes y después del cambio.

**Resultado en holdout: el efecto de escala del baseline global.** Al ser
un baseline compartido por todo el tráfico (no un modelo por usuario), a
mayor volumen aumenta la probabilidad de que tráfico legítimo caiga en la
cola de la distribución solo por azar — es la fuente principal del FPR
distinto de cero incluso al 0% de tráfico malicioso, y de los 3 false
blocks observados en holdout (sección 8).

## 7. Enriquecimiento ASN

**Problema.** El challenge exige enriquecer IPs con al menos una fuente
pública/gratuita de ASN, y `credential_stuffing` necesitaba un
`NetworkResolver` real para dejar de depender del placeholder inerte
(sección 1).

**Decisión.** `internal/asn` consulta RIPEstat (API pública, sin costo)
por IP, con caché positivo con TTL (evita repetir la misma consulta),
timeout total por consulta (incluye espera de cupo de concurrencia) y
**fail-open**: si el proveedor no responde a tiempo o está caído, el
detector sigue corriendo con esa IP como "ASN desconocido" — un proveedor
externo caído nunca puede tumbar ni bloquear el motor.

**Limitación explícita: RIPEstat no es apto como lookup síncrono a
escala.** Es una API pública gratuita, sin garantía de latencia ni de
disponibilidad — aceptable para este prototipo (con caché, timeout y
fail-open), pero no para un volumen de producción alto sin un
enriquecimiento asíncrono/propio (ver sección 12).

**Limitación con el dataset sintético del propio proyecto.** Las IPs
generadas por `internal/datagen` usan rangos reservados para
documentación (RFC 5737), que nunca resuelven contra un proveedor real —
por eso el tuning/holdout usan `datagen.SimulatedASNResolver`
(determinista, offline, por prefijo `/24`), nunca RIPEstat real, y la
integración con RIPEstat se verificó aparte, contra IPs públicas reales.

**Verificado con RIPEstat real**: 30 IPs públicas, confirmando el
comportamiento de caché (miss en `Observe`, hit en `Evaluate` para la
misma IP dentro del mismo evento) y la resolución real de ASN.

## 8. Política de decisión

**El contrato de `Decision`.** `Action`
(`ALLOW`/`CHALLENGE`/`BLOCK`), `ConfidenceScore`, `AttackVector`,
`EntityID`, evidencia (`ContributingSignals`) y una `Explanation` en
texto — siempre presente, incluso en `ALLOW`, para que toda decisión
quede auditable.

**`Policy`: dos umbrales sobre el `RiskScore`.** `ChallengeThreshold` y
`BlockThreshold` traducen el score combinado en una acción. Están
downstream de los detectores — se calibran por separado, dejando
`ScoreFloor` de los tres detectores sin cambios, para aislar su efecto.

**Optimización: reaplicar Policy sin re-correr detectores.** Como
`RiskScore`/`AttackVector` no dependen de los thresholds de Policy, se
agregó `Policy.ActionFor`/`tuning.ReapplyPolicy`, que reaplican Policy
sobre decisiones ya calculadas — verificado con un test de equivalencia
bit-a-bit contra una corrida completa. El sweep de 9 combinaciones corrió
en menos de 1 segundo gracias a esto.

**Calibración.** Un sweep de 9 combinaciones (`Challenge` ∈ {0.50, 0.55,
0.60}, `Block` ∈ {0.70, 0.75, 0.80}) mostró que subir `Challenge` reduce
el FPR de forma monótona pero corta el recall casi a la mitad (de 0.50 a
0.60). Se eligió **`ChallengeThreshold=0.50`, `BlockThreshold=0.75`** como
punto intermedio: 0.55/0.60 sacrificaban demasiado recall; `Block=0.80`
era demasiado conservador frente a los RiskScores maliciosos observados;
`Block=0.70` no tenía margen suficiente contra un dataset legítimo que no
estresa todos los patrones benignos posibles.

**`FalseBlockRate=0` en las 9 combinaciones de tuning se documentó
explícitamente como una propiedad de esos datasets, nunca como
garantía** — no se debía asumir que se mantendría igual contra holdout o
tráfico real.

**Configuración final:**

| Parámetro | Valor |
|---|---|
| ChallengeThreshold | 0.50 |
| BlockThreshold | 0.75 |
| ScoreFloor (los tres detectores) | sin cambios |

**Resultado en holdout: la garantía no generalizó.** Aparecieron 3 falsos
BLOCK reales (`FalseBlockRate=0.0008`, sobre tráfico 0% malicioso) — no
vistos en ningún momento de tuning. Confirma que la ausencia de false
blocks en tuning era una propiedad de esos 3 seeds, no del detector.
Originados en `statistical_anomaly` (sección 6), no en los otros dos
detectores.

## 9. Observabilidad

**Problema.** Cumplir el requisito de observabilidad del challenge con
una solución pequeña, local, reproducible y fácil de explicar: métricas
reales del motor, visibles en un dashboard provisionado automáticamente.

**Decisión — arquitectura.**
```
cmd/engine (Go) --OTLP/gRPC--> OpenTelemetry Collector --scrape--> Prometheus --query--> Grafana
```
Se descartó exponer `/metrics` directamente desde `cmd/engine` (el
exportador Prometheus del propio SDK de OTel): acoplaría el proceso Go al
formato de exposición de Prometheus específicamente; con OTLP, el proceso
nunca sabe qué backend hay detrás.

**Fail-open: el diseño central de este componente.** Sin
`--otel-endpoint`, o si el Collector no responde dentro del timeout de
conexión al arrancar, el motor usa instrumentación no-op y sirve tráfico
exactamente igual — un Collector caído nunca es motivo para no arrancar ni
para dejar de responder requests, solo para quedarse sin métricas.

**Métricas reales, verificadas contra el stack corriendo, no asumidas:**

| Métrica | Tipo | Labels | Qué responde |
|---|---|---|---|
| `waf_decisions_total` | Counter | `action`, `attack_vector` | Decisiones por resultado |
| `waf_detector_findings_total` | Counter | `detector` | Qué detector dispara, incluso el que pierde el desempate |
| `waf_anomaly_score_bucket` | Histogram | ninguno | Distribución completa del score de `statistical_anomaly`, no solo la cola que dispara |
| `waf_asn_cache_total` / `waf_asn_resolve_total` / `waf_asn_provider_duration_seconds` | Counter/Counter/Histogram | `result` | Efectividad del caché de ASN y latencia real del proveedor |
| `http_server_request_duration_seconds` | Histogram | `http_route`, etc. | Latencia/volumen HTTP end-to-end (automático, `otelhttp`) |

**Cardinalidad.** Ningún label es `client_ip`, `request_id`, `entity_id`,
`session_id`, `login_user_hash`, ruta cruda ni un número de ASN
individual — todos los labels son conjuntos fijos y chicos (máximo
observado: 9 series en `waf_decisions_total`).

**Cobertura del requisito de observabilidad del challenge.**
`requests_analyzed_total`/`decisions_by_action_total` están cubiertos por
`waf_decisions_total` (total = suma de todas las series; "por acción" = el
label `action`). `fp_rate` **nunca es una métrica runtime**: requiere
ground truth, y el motor no tiene acceso a ground truth en ningún momento
de su ejecución (sección 1) — calcularlo en vivo sería una proxy
inventada. El FPR real se calcula en el pipeline de evaluación offline
(sección 10). `anomaly_score_histogram` era el único gap real, cerrado con
`waf.anomaly.score` (arriba) — se registra en cada evaluación, dispare o
no. `model_inference_duration` y `llm_call_duration` no aplican: no hay
modelo ML entrenado (es estadístico, Welford + z-scores) ni LLM en
runtime.

**Adenda — vulnerabilidad de dependencias.** Una alerta marcó `grpc` con
una vulnerabilidad HIGH no alcanzable desde este código (se usa solo como
cliente, nunca como servidor xDS); se aplicó igual el bump de parche
porque no tenía costo ni riesgo.

## 10. Evaluación y calibración

**Estrategia: tuning → freeze → holdout único → sin retuning posterior.**
Toda calibración (secciones 4, 5, 6 y 8) se hizo contra datasets de tuning
(seeds 101-103), nunca contra el dataset de reporte ni contra holdout. Una
vez congelada la configuración completa (checkpoint pre-holdout), se
corrió el conjunto de holdout (seeds 201/202/203, nunca vistas durante la
calibración) **una única vez**. No se propuso ningún threshold nuevo a
partir de esos resultados — detector config, Policy y ScoreFloor
permanecieron exactamente como se habían congelado.

**Infraestructura.** `internal/datagen` genera tráfico legítimo y de
ataque con ground truth separado (`internal/groundtruth`, sección 1), con
distribuciones adversariales a propósito (para que el tráfico sintético no
sea artificialmente fácil de distinguir). `internal/tuning` construye un
`BehavioralDecider` con estado fresco por corrida (ninguna corrida
contamina a la siguiente) y corre el motor real en memoria, sin HTTP.
`internal/baseline` (rate limiter tradicional por IP, línea base de
comparación) y `cmd/eval`/`internal/eval` (evaluador genérico, compara
cualquier `decisions.jsonl` contra el ground truth) existen aparte — el
motor conductual real se evalúa directamente en memoria vía
`internal/tuning`, nunca por ese archivo intermedio (ver README para cómo
usar cada herramienta).

**Sweep combinado (`slow_scan` + `statistical_anomaly`).** Confirmó que
`S3+A3` era la combinación con mejor recall general (broad@30%: 0.75 vs.
0.49 del baseline) a cambio de un costo chico y mecánicamente explicado en
`credential_stuffing` (la asistencia de `statistical_anomaly` volviéndose
un poco menos frecuente) y una FPR apenas mayor — se aprobó como base para
calibrar `credential_stuffing` (sección 4) y, después, Policy (sección 8).

**Resultados finales — holdout (seeds 201-203, pooled), Final vs.
Baseline:**

| Ratio | Métrica | Baseline | Final |
|---|---|---|---|
| 0% | FPR (broad) / FalseBlockRate | 0.0529 / 0.0000 | 0.0617 / 0.0008 |
| 10% | Precision / Recall / F1 (broad) | 0.7116 / 0.8479 / 0.7738 | 0.7182 / 0.9549 / 0.8198 |
| 30% | Precision / Recall / F1 (broad) | 0.9468 / 0.4842 / 0.6407 | 0.9621 / 0.8837 / 0.9213 |

**Lectura.** Final supera a Baseline en holdout en prácticamente todas las
métricas de cobertura — el patrón de tuning se reproduce. La mayoría de
las métricas generalizan bien o incluso mejoran (Broad Recall, F1); la
señal más débil está concentrada en dos lugares ya documentados como
limitación antes de correr holdout: `CS RecallDetector@10%` (sección 4) y
los 3 falsos BLOCK / FPR@0% (`statistical_anomaly`, baseline global —
secciones 6 y 8). Ninguna de las dos fue una sorpresa cualitativa.

**Limitación de método.** Cada corrida (tuning y holdout) parte de estado
limpio por diseño, así que la comparación es justa — pero en producción
real el estado persiste indefinidamente, algo que ningún holdout de este
tipo puede medir.

## 11. Rendimiento

**Problema.** Medir el rendimiento del motor (latencia de decisión pura y
throughput HTTP end-to-end) antes de considerar cualquier optimización,
sin cambiar ningún detector/threshold/Policy/ScoreFloor — la configuración
usada es exactamente la final congelada (secciones 4, 5, 6 y 8).

**Decisiones de harness.** Microbenchmark (`go test -bench`, tres
perfiles normal/mixed/attack-heavy) con timestamps reescritos para quedar
estrictamente monotónicos entre vueltas del escenario (evita sesgar los
watermarks de los detectores, sección 3). Load test HTTP con un cursor
atómico único compartido entre todos los workers de una repetición
(`request n -> events[n % len(events)]`, nunca cada worker desde el evento
0) y cliente HTTP con pool de conexiones dimensionado para la concurrencia
pedida (el default de Go fuerza a reabrir conexión en cada request bajo
concurrencia alta, midiendo el costo de abrir conexiones en vez del costo
real de servir). Percentiles: mediana de percentiles calculados por
repetición, nunca sobre las muestras de las 3 repeticiones mezcladas en un
pool único. Warmup y medición son dos fases de código físicamente
separadas, no una condición sobre un único loop. ASN determinista
(`SimulatedASNResolver`) en todo el load test, nunca RIPEstat real.

**Microbenchmark (`BehavioralDecider.Decide()`, aislado, sin red):**
≈9.7–10.5 μs/op, ≈16 KB/op, 45–46 allocs/op según el perfil.

**Load test HTTP (matriz perfil × concurrencia {1,10,25,50,100}, 3
repeticiones):** throughput entre ≈2.000 y ≈3.000 req/s, **cero errores**
en las 45 combinaciones, saturación (el throughput deja de crecer de
forma significativa) observada alrededor de concurrencia 50. p95/p99
crecen aproximadamente lineal con la concurrencia una vez saturado.

**Hallazgo sin causa atribuida.** El tráfico attack-heavy mostró
throughput HTTP local ≈20-27% mayor que el legítimo, pese a ser ≈5% más
caro en el microbenchmark aislado. El análisis offline (tamaño de
request/response, cardinalidad de entidades, diversidad de rutas) no
encontró ninguna explicación de soporte — no se afirma ninguna causa; se
trata como comportamiento dependiente de la carga de trabajo del
benchmark local, no como evidencia de que el tráfico malicioso sea
intrínsecamente más barato de procesar.

**Comparativo OTel pareado (dos corridas, measurement=10s y 35s).** Todos
los deltas quedaron por debajo del 5%, sin dirección consistente entre
métricas — comparable a la variabilidad normal entre repeticiones. **No
se observó overhead material de OpenTelemetry bajo las condiciones
locales probadas** — nunca "sin overhead" ni "cero overhead", una
afirmación más fuerte de lo que estos datos permiten.

**Ambos resultados HTTP son de un entorno local (loopback, cliente y
servidor comparten proceso y máquina) — no representan capacidad de un
servidor de producción desplegado por separado, y no se extrapolan
linealmente a "cuántos servidores necesito" (sección 12).**

## 12. Escalabilidad

**Alcance.** Documento puramente conceptual (`docs/scaling-1b-rph.md`,
con su versión Mermaid en el README), sin ninguna implementación: no se
agregó infraestructura distribuida, ninguna dependencia nueva, y no se
modificó ninguna lógica de detección — Policy, ScoreFloor y los umbrales
calibrados en el holdout se mantienen exactamente iguales.

**Idea central: separar un fast path de un analytics path.** El **fast
path** (síncrono) solo lee un **Risk State Store** — un riesgo dinámico
que los detectores actualizan continuamente, nunca una decisión ALLOW
cacheada de forma fija — y aplica Policy. El **analytics path**
(asíncrono) recibe una copia de cada evento por un Event Stream y corre
ahí los tres detectores, particionados según a qué entidad correlacionan:
`slow_scan` por IP/sesión, `credential_stuffing` por ASN,
`statistical_anomaly` por cohorte — así cada detector sigue viendo todo el
historial de una entidad aunque el tráfico se reparta entre cientos de
máquinas.

**Otros componentes conceptuales.** Blocklist distribuida con TTL,
consultada antes del análisis completo (evita repetir trabajo contra un
atacante ya identificado); backpressure explícito entre los dos caminos
(el analytics path puede atrasarse respecto al fast path; ese atraso se
mide y se gestiona, no se ignora).

**Limitación estructural: cold-start.** Una entidad nueva no tiene
historia conductual todavía, así que sus primeras requests pasan mientras
se acumula evidencia — el mismo fenómeno medido empíricamente como
*detection delay* en tuning/holdout (mediana ~24-26 requests para
credential stuffing, ~3-10 para slow scan).

**Alta disponibilidad: fail-open/fail-closed explícito por componente.**
Para la caída del Risk State Store en particular, se propone degradación
controlada (CHALLENGE como default durante la caída, nunca ALLOW ni
BLOCK, con alerta) en vez de un "default seguro" implícito — el trade-off
disponibilidad vs. seguridad queda documentado, no escondido.
