# PROJECT_STATE — tracker vivo

Estado del proyecto por módulo. Lo actualiza el agente en cada hito. Para el
protocolo, ver `AI_WORKFLOW.md`; para el diseño, `ARCHITECTURE.md`.

_Última actualización: 2026-10-05._

## Leyenda
✅ hecho · 🚧 en curso · 🧊 backlog

## Rama hardware (DMA)
- ✅ Teoría de detección (`docs/Architecture_and_Theory.md`).
- ✅ Auditoría estática IOMMU WinDbg (`scripts_windbg/iommu_audit.js`).
- ✅ Consumidor ETW de faults + correlación (parseo schema-driven BDF/IOVA).
- 🧊 Confirmar en máquina real: GUID del provider de fault, `DEVPKEY` de postura.

## Rama software (Ring 0/3)
- ✅ Doc de manipulación por software (`docs/Software_Tampering_Detection.md`).
- ✅ `byovd_detector` + catálogo CSV + heurística de ruta.
- ✅ `image_load_consumer` (ETW image-load en vivo -> BYOVD) + captura de pila.
- ✅ `stack_spoof_detector` (5 checks, lógica pura) + tests en CI.
- ✅ `Win32StackEnv` — `IStackEnv` en vivo para el proceso actual
  (VirtualQueryEx / RtlLookupFunctionEntry / thunks / call-preceded) + modo
  `stackself`. [XPROC] cross-process pendiente.
- 🧊 Cablear pilas ETW -> `ThreadStack` -> `Detector` en `imgwatch`.  →  ✅
  (`imgwatch` extrae los frames user-mode de la pila ETW y, en una alerta BYOVD,
  los valida cross-process con `Win32StackEnv` + `Detector`; unwind auto-gateado
  y TebBounds omitido por falta de TEB del hilo — honesto).
- 🧊 DKOM: requiere componente de kernel (callbacks) — fase posterior.

## DevEx / infraestructura
- ✅ CI Windows/MSVC `/W4 /WX` + `ctest` (GitHub Actions).
- ✅ Doc pedagógica (`docs/Concepts_101.md`) + onboarding en README.
- ✅ `AI_WORKFLOW.md`, `ARCHITECTURE.md`, este tracker.
- ✅ Revisión de seguridad del C++ (inline; el subagente independiente quedó
  bloqueado por el safeguard cyber de la plataforma). Sin bugs de memoria de alta
  severidad; 3 findings de robustez corregidos: (1) call-preceded no "acusa"
  cuando el código previo es ilegible (evita falso positivo), (2) el CSV conserva
  comas en `reason`, (3) etiqueta `(pila)` para findings de ámbito global.
- ✅ Hook pre-commit (gate local de lógica pura con g++) + instalador.
- 🧊 Entorno de validación cross-process para el stack env (fase posterior).

## Backlog de tests
- 🧊 Más vectores de `stack_spoof_detector`: anomalías combinadas, pila de un solo
  frame, direcciones en el límite exacto del TEB.
- 🧊 Tests de `byovd_detector` (driver limpio / nombre en lista / ruta escribible).
