# ARCHITECTURE — manifiesto

Visión de ingeniería del proyecto: capas, fronteras y por qué están donde están.
Para el "qué es" pedagógico, ver `docs/Concepts_101.md`.

## Propósito
Piezas de un **EDR defensivo** para Windows que **detectan** manipulación del
sistema, por dos ramas:
- **Hardware (DMA):** teoría + auditoría estática del IOMMU (`scripts_windbg/`) +
  consumidor ETW de faults (`src_etw_consumer`, ruta DMA).
- **Software (Ring 0/3):** detección de BYOVD, DKOM y call-stack spoofing.

## Capas y fronteras
```
          +-----------------------------------------------------+
  SO  --> |  Entornos / fuentes (dependientes de Windows)       |
          |  ETW sessions · TDH · SetupAPI · (futuro) Win32Stack|
          +--------------------------┬--------------------------+
                                     │  interfaces / structs POD
                                     ▼
          +-----------------------------------------------------+
 PURO --> |  Lógica de detección (independiente del SO)         |
          |  byovd::Detector · sspoof::Detector (5 checks)      |
          +-----------------------------------------------------+
                                     ▲
                                     │  frames/eventos sintéticos
          +-----------------------------------------------------+
TEST ---> |  Tests (FakeEnv, CSV sintético) — sin SO vivo       |
          +-----------------------------------------------------+
```

**Regla de oro:** la lógica de detección **no llama al SO**. Recibe hechos ya
resueltos a través de interfaces/estructuras POD. El SO vive en los bordes.

- `sspoof::IStackEnv` es la frontera explícita: en producción la implementa
  `Win32StackEnv` (VirtualQuery / RtlLookupFunctionEntry / thunks / call-preceded);
  en test, un `FakeEnv` con frames a mano. Mismo detector, dos entornos.
- `byovd::Detector` recibe un `ImageLoad` (POD); quién lo rellena (el
  `ImageLoadConsumer` de ETW en vivo, o un test) le es indiferente.

**Beneficio:** la lógica se prueba de forma determinista en CI con `g++`/`ctest`
sin necesidad de una máquina Windows, y el núcleo no se contamina de detalles del
SO (mantenibilidad + superficie de ataque mínima).

## Módulos (src_etw_consumer/src)
| Módulo | Capa | Rol |
|---|---|---|
| `types.h` | puro | `FaultEvent` (DMA): SID 16b -> BDF |
| `etw_consumer.*` | SO | sesión ETW de faults DMA + extracción TDH |
| `correlation.*` | SO | BDF -> devnode (SetupAPI) + fingerprint + alerta |
| `byovd_detector.*` | **puro** | catálogo vulnerables + heurística de ruta -> veredicto |
| `image_load_consumer.*` | SO | ETW image-load en vivo -> `byovd::Detector` (+stack trace) |
| `stack_spoof_detector.*` | **puro** | 5 comprobaciones de spoofing de pila |
| `win32_stack_env.*` | SO | `IStackEnv` real (en construcción) |

## Datos de record (editables sin recompilar)
- `byovd/known_vulnerable.csv` — catálogo de drivers vulnerables (semilla
  compilada + este CSV en runtime). Elegido CSV sobre JSON para no introducir un
  parser de terceros que pueda romper bajo `/WX`.

## Build, test y gate
- Build: CMake (`src_etw_consumer`), generador VS por defecto del runner, x64.
- Flags: `/W4 /WX /permissive- /guard:cf`; link `/INTEGRITYCHECK /guard:cf`.
- Tests: `ctest` (target `stack_spoof_tests`, lógica pura).
- **CI (GitHub Actions) es el gate autoritativo.** Pre-commit local = atajo
  rápido de lógica pura con `g++` (ver `AI_WORKFLOW.md` §3).

## Huecos "confirmar en build" (honestidad, no fantasmas)
- GUID del provider de fault DMA (ruta DMA).
- Provider/keyword/Event Id de image-load y nombre de la propiedad de ruta.
- Clave `DEVPKEY` de postura DMA.
- Unwind/clasificación cross-process en `Win32StackEnv` (primera versión:
  proceso actual; cross-process documentado como extensión).

## Límite de confianza
Todo corre en VTL0: es una capa de telemetría/auditoría, no la raíz de confianza
(esa vive en VTL1/VBS). Ver `docs/Architecture_and_Theory.md` §12.
