# DMA-EDR PoC — consumidor ETW + correlación de postura DMA

Prueba de concepto **defensiva (blue team)**. Captura eventos de PnP / DMA-guard
del kernel vía ETW, normaliza el tuple `{BDF, IOVA}` y lo cruza con SetupAPI para
resolver el devnode físico, su identidad (fingerprint VEN/DEV) y su postura de
DMA remapping. Es el segundo nivel de un diseño EDR: **el kernel es el sensor;
esto es el motor de correlación.**

## Estructura

```
dma-edr-poc/
├─ CMakeLists.txt        # build + piezas build-time de PPL (/INTEGRITYCHECK, firma)
├─ README.md
└─ src/
   ├─ types.h            # FaultEvent; decodifica SID(16b) -> bus/dev/func
   ├─ etw_consumer.h/.cpp# sesión ETW real-time + extracción TDH del payload
   ├─ correlation.h/.cpp # BDF -> devnode -> DMA policy + fingerprint + alerta
   └─ main.cpp           # modos run / install (PPL-AM) / enumprops
```

## Build

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## La realidad de PPL (no es un manifiesto)

Protected Process Light **anti-malware** no se concede con un application
manifest. Se compone de tres piezas, repartidas entre build, firma y runtime:

| Pieza | Dónde | Qué hace |
|-------|-------|----------|
| `/INTEGRITYCHECK` | linker (CMakeLists) | el loader exige firma válida al cargar |
| Recurso ELAM (`elam.rc`) | build | embebe la info del certificado AM |
| Certificado anti-malware | firma post-build | emitido por Microsoft (EKU 1.3.6.1.4.1.311.61.4.1) |
| `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT` | runtime (`main.cpp install`) | lanza el servicio protegido |

Sin el certificado AM de Microsoft, el servicio protegido **no arranca**: es un
peaje de programa, no de código. Hasta tenerlo, prueba en modo `run` normal
(requiere admin para abrir la sesión ETW).

## Dos huecos que debes cerrar EN TU BUILD (y por qué los dejo abiertos)

No hay documentación pública estable para estos dos datos; hardcodearlos de
memoria te mandaría a perseguir fantasmas. Se resuelven en la propia máquina:

1. **GUID del provider ETW** (`etw_consumer.cpp`, `kProvider`):
   ```
   logman query providers | findstr /i "dma pnp device guard"
   ```
   Ancla sólida: `Microsoft-Windows-Kernel-Pnp`. Los nombres de propiedad del
   payload (`SourceId` / `Address`) se confirman con `tracerpt` sobre un `.etl`.

2. **Clave DEVPKEY de postura DMA** (`correlation.cpp`):
   ```
   edrsvc enumprops <bus> <dev> <func>
   ```
   vuelca TODAS las claves del devnode; localiza la clave DMA real y pégala con
   `DEFINE_DEVPROPKEY`. Hasta entonces la postura se reporta como "desconocida"
   en vez de leer una clave inventada.

## Nota de alcance

Corre en VTL0: es **una** capa de correlación, no la raíz de confianza. La
medición blindada frente a un adversario Ring-0 vive en VTL1 (VBS). Este PoC
asume un sensor de kernel honesto y se concentra en convertir sus eventos en
alertas accionables.
