# WAF Behavior Engine

Motor de decisión en Go que analiza metadata de tráfico HTTP y detecta dos
categorías de ataque de baja intensidad — **credential stuffing distribuido**
y **enumeración / escaneo lento** — mediante técnicas multicapa (reglas
conductuales, correlación entre entidades y un modelo de anomalías), con
explicación de cada decisión y observabilidad completa.

> **Estado:** en construcción (Fase 0 — datos de prueba y evaluación).
> Este README se completa a medida que avanzan las fases del proyecto.

## Entorno de pruebas

| | |
|---|---|
| Hardware | Apple M3, 16 GB RAM |
| Sistema operativo | macOS (Darwin 24.6.0) |
| Go | 1.23.1 (darwin/arm64) |
| Docker | 27.3.1 |
| Git | 2.39.5 |

## Cómo ejecutar

_Pendiente — se documenta a medida que existan `cmd/datagen`, `cmd/eval` y
`cmd/engine`._

## Arquitectura

_Pendiente._

## Enriquecimiento de IP

_Pendiente._

## Métricas

_Pendiente._

## Resultados (0% / 10% / 30% de tráfico malicioso)

_Pendiente._

## Escalado a 1.000 millones de requests/hora

_Pendiente — propuesta conceptual, sin implementación._

## Extras implementados

_Pendiente._
