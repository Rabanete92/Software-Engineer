# dma-edr-research

[![build](https://github.com/Rabanete92/Software-Engineer/actions/workflows/build.yml/badge.svg)](https://github.com/Rabanete92/Software-Engineer/actions/workflows/build.yml)

Investigación **defensiva (blue team)** sobre detección de ataques DMA por
hardware y diseño de telemetría EDR en Windows. Reúne la teoría dura (bus PCIe/TLP,
fingerprinting, IOMMU/VT-d, reporte de faults, el invariante de comportamiento),
una herramienta de auditoría estática del IOMMU para WinDbg, y un consumidor ETW
con correlación de postura DMA.

> Alcance estrictamente defensivo: auditoría de integridad, detección de anomalías
> y telemetría. Los mecanismos de ataque se documentan al nivel necesario para
> derivar firmas e invariantes de detección, no para ejecutarlos. No contiene
> exploits, primitivas armadas ni bypasses operativos.

## Rampa de entrada (onboarding)

**¿Nuevo en el proyecto?** Empieza por [`docs/Concepts_101.md`](docs/Concepts_101.md):
explica con analogías (sin bajo nivel ni código) qué es BYOVD y qué es el
call-stack spoofing, que es lo que defendemos.

**¿Qué es esto?** Investigación **defensiva (blue team)** que construye piezas de
un EDR para Windows: telemetría y heurísticas que **detectan** manipulación del
sistema —por hardware (ataques DMA) y por software (BYOVD, DKOM, spoofing de
pila)—. Observa y clasifica; no ataca.

**Mapa en 30 segundos:**
- `docs/` — la teoría y la pedagogía (empieza por `Concepts_101.md`).
- `scripts_windbg/iommu_audit.js` — auditoría estática del IOMMU (rama hardware).
- `src_etw_consumer/` — el servicio C++ (rama software): consumidores ETW y los
  detectores (`byovd_detector`, `stack_spoof_detector`).

**Arquitectura limpia (lo que hay que entender antes de tocar código):** la
*lógica* de detección está **separada del sistema operativo**. Por ejemplo,
`stack_spoof_detector` no llama a ninguna API de Windows: recibe los hechos de
cada frame a través de una interfaz, `IStackEnv` (inyección de dependencias). En
producción esa interfaz la implementará un entorno Win32 real; en los tests la
implementa un `FakeEnv` con datos sintéticos. Ventaja: la lógica se prueba de
forma determinista **sin necesidad de una máquina Windows viva**, y el motor no
se contamina con detalles del SO.

**Compilar y correr los tests** (requiere CMake y un toolchain MSVC; en Windows):

```
cd src_etw_consumer
cmake -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Los tests unitarios (`test/stack_spoof_tests.cpp`) no necesitan privilegios ni
hardware: validan la lógica del detector con frames sintéticos. El CI
(GitHub Actions, `.github/workflows/build.yml`) hace exactamente estos pasos en
cada push bajo `/W4 /WX` (cero warnings tolerados).

## Estructura

```
dma-edr-research/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── Concepts_101.md                # pedagógico, sin bajo nivel (empieza aquí)
│   ├── Architecture_and_Theory.md     # DMA/EDR: teoría de detección (hardware)
│   └── Software_Tampering_Detection.md # BYOVD / DKOM / call-stack spoofing (software)
├── scripts_windbg/
│   └── iommu_audit.js                 # auditoría estática VT-d (Root/Context/SLPT)
├── src_etw_consumer/
│   ├── CMakeLists.txt                 # build + /INTEGRITYCHECK + estructura PPL
│   ├── README.md                      # realidad de PPL y huecos a cerrar por build
│   └── src/
│       ├── types.h                    # FaultEvent; SID(16b) -> bus/dev/func
│       ├── etw_consumer.h/.cpp        # sesión ETW real-time + extracción TDH
│       ├── correlation.h/.cpp         # BDF -> devnode -> DMA policy + fingerprint
│       └── main.cpp                   # run / install (PPL-AM) / enumprops
└── build/                             # artefactos de compilación (ignorado por git)
```

## Componentes

### `scripts_windbg/iommu_audit.js`
Script DbgModel (JavaScript) para WinDbg. Recorre `RTADDR_REG → Root → Context →
SLPT` leyendo memoria física, y vuelca `[BDF] → [Domain ID] → [HPAs mapeadas]` como
baseline. Señales: `[!! PASS-THROUGH]` (TT=2), bytes totales por dominio (salto
volumétrico a GB), y diff de SLPTPTR/DID/RTADDR entre snapshots.

```
0: .scriptload scripts_windbg\iommu_audit.js
1: dx @$iommuaudit("0xFED90000")      # base MMIO del DRHD (confirmar en la DMAR)
```

### `src_etw_consumer/`
Servicio user-mode (C++): consume eventos de PnP/DMA-guard vía ETW, normaliza
`{BDF, IOVA}` y lo cruza con SetupAPI para resolver el devnode, su identidad
(VEN/DEV) y su postura de DMA remapping. Ver su README para la realidad de PPL y
los dos datos a resolver por build (GUID de provider y clave DEVPKEY de postura DMA).

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Detección de manipulación por software (nuevo)
Ampliación hacia vectores puramente por software (Ring 0 / Ring 3). Ver
`docs/Software_Tampering_Detection.md` para la auditoría de **BYOVD**, **DKOM** y
**call-stack spoofing** (mecánica conceptual + telemetría/IoCs + hardening).
Primer módulo en código: `byovd_detector` — puntúa una carga de driver contra el
catálogo editable `src_etw_consumer/byovd/known_vulnerable.csv` + heurística de ruta.

```
edrsvc imgwatch [catalogo.csv]                   # watch de image-load en vivo -> BYOVD
edrsvc byovd <catalogo.csv|-> <ruta_driver> [kernel]   # evaluación puntual de una ruta
```

Módulo `stack_spoof_detector`: valida pilas de llamadas con 5 comprobaciones
(return respaldado por imagen, coherencia de unwind, límites del TEB,
call-preceded y terminación en el thunk de arranque). Lógica pura con tests
unitarios ejecutados en CI (CTest).

## Estado

Prueba de concepto académica. Corre en VTL0: es una capa de auditoría/telemetría,
no la raíz de confianza (esa vive en VTL1/VBS). Ver §12 del documento de teoría.
