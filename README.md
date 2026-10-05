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

## Estructura

```
dma-edr-research/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
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

## Estado

Prueba de concepto académica. Corre en VTL0: es una capa de auditoría/telemetría,
no la raíz de confianza (esa vive en VTL1/VBS). Ver §12 del documento de teoría.
