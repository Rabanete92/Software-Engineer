# Arquitectura y Teoría — Detección de DMA Attacks y Telemetría EDR en Windows

> Base de estudio técnica. Investigación **defensiva (blue team)**: comprender la
> mecánica del ataque DMA con la profundidad justa para instrumentar su detección.
> El principio rector de todo el documento es el **invariante de comportamiento**:
> un dispositivo de lectura por DMA tiene, por definición, que acceder a memoria
> que no le corresponde — y eso deja un rastro que ningún spoofing elimina.

## Índice

1. [Modelo de amenaza y encuadre](#1-modelo-de-amenaza-y-encuadre)
2. [Mecánica del bus PCIe y TLP](#2-mecánica-del-bus-pcie-y-tlp)
3. [Fingerprinting de hardware PCIe](#3-fingerprinting-de-hardware-pcie)
4. [IOMMU (VT-d / AMD-Vi)](#4-iommu-vt-d--amd-vi)
5. [Reporte de faults: FSTS, FRCD, MSI](#5-reporte-de-faults-fsts-frcd-msi)
6. [Clasificación de confianza y el flanco interno](#6-clasificación-de-confianza-y-el-flanco-interno)
7. [El invariante de comportamiento](#7-el-invariante-de-comportamiento)
8. [Telemetría en el kernel: callbacks oficiales](#8-telemetría-en-el-kernel-callbacks-oficiales)
9. [ETW: observación sin Ring 0](#9-etw-observación-sin-ring-0)
10. [Minifilters y WFP (visión general)](#10-minifilters-y-wfp-visión-general)
11. [Catálogo de asserts de detección](#11-catálogo-de-asserts-de-detección)
12. [Aislamiento por hardware y límites (VBS/VTL)](#12-aislamiento-por-hardware-y-límites-vbsvtl)

---

## 1. Modelo de amenaza y encuadre

El adversario de referencia es un **dispositivo DMA malicioso** — típicamente un
FPGA (familias Artix/Kintex sobre placas tipo "screamer"/"captain") montado en
una ranura PCIe/M.2 interna — que lee la memoria física del host sin ejecutar
una sola instrucción en la CPU. El objetivo defensivo no es impedir el DMA (medio
sistema moderno lo usa) sino **distinguir el dispositivo impostor del legítimo** y
**detectar accesos a memoria que no corresponden** a ese dispositivo.

Caso de estudio: anti-cheat de kernel (p. ej. EAC) como EDR especializado. Mismo
problema que un EDR corporativo —observar un endpoint hostil desde dentro— con
restricciones más duras (latencia, hardware de consumo, adversario con acceso
físico total). La presión evolutiva: cada capa de aislamiento no *elimina* al
atacante, lo *empuja a un terreno más detectable y caro*. HVCI lo saca de la
ejecución de código en kernel y lo mete en ataques data-only; esos, a su vez,
dejan anomalías estructurales; cerrado el software, la presión se desplaza al
DMA por hardware, que tiene firmas propias.

---

## 2. Mecánica del bus PCIe y TLP

**DMA es anterior y ortogonal a la pila de seguridad del SO.** El Object Manager,
los callbacks de `Ob`, los `ACCESS_MASK` — todo vive en el camino de ejecución de
la CPU. Un acceso DMA no pasa por ahí: el dispositivo maestro del bus habla
directamente con el memory controller (en el uncore de la CPU) a través del
enlace PCIe. La CPU está fuera del lazo, y por eso no hay callback software donde
engancharse: **no hay transición a Ring 0 que interceptar**.

PCIe es una red conmutada punto a punto de paquetes serializados — *Transaction
Layer Packets* (TLP). Para leer memoria del host, un endpoint emite un TLP
**Memory Read Request (MRd)**:

- **Requester ID** (en el header): el `Bus:Device:Function` (BDF) del originador.
  El root complex siempre sabe qué BDF originó cada transacción — y ese es el
  gancho sobre el que el IOMMU cuelga su política.
- **Address**: dirección física *tal como la ve el dispositivo* (una *I/O virtual
  address*, IOVA). Sin IOMMU, IOVA == dirección física real. Con IOMMU, pasa por
  traducción antes de tocar DRAM.
- La respuesta vuelve en TLP **Completion with Data (CplD)**, correlacionados por
  un `Tag` del header.

**El problema previo del atacante** (y parte de la dificultad real): el
dispositivo ve direcciones físicas; el juego/proceso opera en virtuales.
Traducir virtual→física requiere la tabla de páginas del proceso, y para eso su
`CR3`/`DirectoryTableBase` (en `nt!_EPROCESS`), que está en memoria del kernel.
El dispositivo DMA puro primero **escanea física** buscando firmas de estructuras
del kernel para reconstruir la traducción. Ese barrido amplio sobre rangos
físicos tiene un perfil de tráfico muy distinto al de un NIC legítimo — señal de
detección (ver §7).

---

## 3. Fingerprinting de hardware PCIe

Modelo: un FPGA que se presenta como dispositivo benigno (NIC, controladora) con
BDF, Vendor/Device ID y config space copiados de hardware real. El defensor juega
a distinguirlo. Superficies de auditoría, de la config space (4 KB, formato PCIe
extendido, capabilities encadenadas):

### 3.1 Config space estándar (Type 0)
- **Discrepancias BAR**: los Base Address Registers declaran tamaño, número y
  atributos (prefetchable, 32/64-bit) de las regiones mapeadas. Un clon del VID/DID
  de un modelo concreto que no reproduce *sus* BARs exactos es incoherente.
- **Power Management capability**: el hardware real implementa D0–D3 con tiempos
  de transición concretos; muchos impostores exponen la capability pero no se
  comportan como silicio al ejercerla.
- **Coherencia del árbol de capabilities**: MSI/MSI-X, PCIe Capability (Link
  Status/Capabilities — anchura y velocidad negociadas), ASPM, AER. La
  inconsistencia entre lo que el dispositivo *dice ser* (Class Code) y lo que
  *implementa* es el núcleo del fingerprinting.

### 3.2 Extended Capabilities (0x100+) — las difíciles de emular
- **Device Serial Number (DSN)**: EUI-64; los 8 bytes altos son el OUI del vendor.
  DSN=0, o OUI del DSN ≠ OUI del Vendor ID declarado, delata.
- **AER (Advanced Error Reporting)**: silicio real acumula correctables con el
  tiempo y responde con semántica concreta; un stub en bitstream no lo reproduce
  de forma realista. **Comportamental**, no copiable.
- **ASPM L0s/L1 exit latency**: la latencia *declarada* en Link Capabilities vs la
  *medida* al forzar L1→L0 está atada al PHY real. Difícil que un FPGA haga
  cuadrar ambas.
- **LTR / L1 PM Substates / ACS / ATS**: más caps atadas a comportamiento o a
  implementación coherente. ATS presente en algo que se declara NIC simple = rojo
  (permite TLPs "ya traducidos").

### 3.3 Principio
**La identidad se clona; la coherencia interna completa y el comportamiento
atado a PHY no.** El fingerprinting robusto (a) compara la cadena completa de caps
contra un *golden reference* por modelo {VEN, DEV, REV, Subsystem}, y (b) **prueba
activa**: ejerce el dispositivo (latencia ASPM, AER bajo error inducido, perfil de
interrupciones MSI-X) en vez de solo *leer* la config space, que es falsificable.

---

## 4. IOMMU (VT-d / AMD-Vi)

El IOMMU es una MMU para dispositivos: se interpone entre el root complex y el
memory controller e intercepta cada TLP de memoria usando el **Requester ID (BDF)**
como índice.

### 4.1 Jerarquía de traducción (VT-d legacy)
```
RTADDR_REG (registro MMIO del DRHD, offset 0x20)
  └─► Root Table          (256 entradas de 128b, indexada por Bus)
        └─► Context Table  (256 entradas de 128b, indexada por Devfn = Dev:Func)
              ├─ Domain ID (DID)
              ├─ Translation Type (TT)
              └─► SLPTPTR → Second-Level Page Tables (9-9-9-9-12, IOVA→HPA)
```
- La base del register block del DRHD la publica la tabla ACPI **DMAR**.
- `RTADDR_REG`: bits [63:12] = Root Table PA; bit 11 = scalable mode (TTM) → la
  jerarquía usa PASID directory/table antes de las SLPT (recorrido distinto).
- **Context Table Entry (CTE)**: Present (bit0), TT (bits[3:2]), SLPTPTR (bits
  [63:12] del qword bajo), DID y Address Width (AW) en el qword alto.
  - `TT=0`: solo second-level (SLPT).
  - `TT=2`: **pass-through** — sin traducción; el dispositivo ve toda la RAM sin
    faults. Estado de "fuga" más limpio.
- AW → niveles: `levels = AW + 2` (AW 0..3 → 2..5 niveles). Shift por nivel:
  `12 + 9*(level-1)`. Hojas: nivel 1 (4K), o PS=bit7 en nivel 2 (2M) / 3 (1G).

### 4.2 Flujo de decisión
1. BDF indexa Root Table → Context Table → dominio + SLPT del dispositivo.
2. Si la IOVA del TLP tiene entrada válida en el dominio → traduce y permite.
3. Si no → **DMA remapping fault**: bloquea y registra.

El SO puede así *acorralar* cada dispositivo en un dominio que solo mapea sus
buffers legítimos. Un MRd contra memoria del juego desde un dominio que no la
incluye → fault, sin datos.

### 4.3 Auditoría de integridad (ver `scripts_windbg/iommu_audit.js`)
Un adversario Ring-0 paralelo que quiera fugar sin faults debe lograr que la
traducción del dispositivo cubra lo que quiere leer. Firmas en memoria:
1. **CTE re-apuntada**: SLPTPTR → page table más permisivo o al SLPT de un
   dominio confiable con mapeos amplios.
2. **DID reasignado**: la CTE adopta el dominio de otro dispositivo.
3. **Entradas inyectadas en el propio SLPT**: PTEs de E/S añadidas que cubren el
   objetivo (el más sutil: no cambia punteros, solo contenido de hojas).
4. **Root Table shadowing**: re-apuntar `RTADDR_REG` a una Root Table paralela.

Auditoría = **diferencial contra baseline limpio**: snapshot de {RTADDR_REG, DID y
SLPTPTR por CTE, conjunto de HPAs por dominio} y comparación periódica. Señal
complementaria barata: tráfico anómalo en la **Invalidation Queue** (`IQH/IQT_REG`,
0x80/0x88), que el atacante suele necesitar para que los cambios surtan efecto.

---

## 5. Reporte de faults: FSTS, FRCD, MSI

Cómo el hardware notifica un fault al kernel (VT-d):

- **Fault Status Register (FSTS_REG)**: `PPF` (primary pending fault), `PFO`
  (overflow — los recording registers se llenaron).
- **Fault Event Control/Data/Address (FECTL/FEDATA/FEADDR_REG)**: un **MSI que
  emite el propio IOMMU**. Es de **flanco con coalescing**: si llueven faults con
  uno ya pendiente, NO dispara un MSI por cada uno — se acumulan hasta `PFO`. ⇒
  **no cuentes faults por interrupciones**; drena los recording registers y vigila
  overflow. Un barrido DMA agresivo puede desbordarlos, y ese overflow es señal.
- **Fault Recording Registers (FRCD_REG)**: array de 128b (nº y offset en
  `CAP_REG`: `NFR`, `FRO`). Cada fault graba:
  - `F` (fault bit; write-1-to-clear),
  - **SID = Requester ID (BDF)** del infractor,
  - `FR` (fault reason),
  - **FI = IOVA** que disparó el fault,
  - `T` (read/write).

El tuple **{BDF, IOVA, tipo, razón, timestamp}** es el evento de telemetría crudo.

**AMD-Vi**: análogo con un **Event Log** en memoria (ring buffer que el IOMMU
rellena por DMA y señala por su MSI), entradas tipo `IO_PAGE_FAULT` con DeviceID,
dirección y flags. Misma filosofía, distinto transporte.

**Realidad de Windows**: el MSI del DRHD lo programa y atiende el **propio kernel**
(`nt!Iommu*`/HAL), base de Kernel DMA Protection. Un driver de tercero **no** puede
registrar su ISR ni mapear esos registros — y tocarlos rompe PatchGuard/HVCI. ⇒
El kernel es el sensor; el EDR consume vía **ETW** (§9), no vía MMIO.

---

## 6. Clasificación de confianza y el flanco interno

La decisión "interno confiable vs externo no confiable" **no vive en el
dispositivo; vive en el firmware describiendo el puerto**. Windows lee dos
propiedades `_DSD` sobre el PCIe root port:

- **`ExternalFacingPort`** — UUID `EFCC06CC-73AC-4BC3-BFF0-76143807C389`, valor 1.
  Marca jerarquías expuestas (Thunderbolt/USB4). Arrancan no confiables.
- **`DmaProperty`** — UUID `70D24161-6DD5-4C9E-8070-705531292865`, valor 1. Marca
  puertos **internos pero accesibles al usuario** (M.2, slots abiertos) para
  enforcement de Kernel DMA Protection. Windows 10 1903+.

**El flanco interno, con precisión**: `DmaProperty` es **opt-in del OEM**. Si el
firmware no lo pone en el `_DSD` de una M.2, Windows la trata como silicio soldado
de fiar — dominio concedido sin exigir soporte de DMA remapping al driver, a menudo
mapeo permisivo o pass-through efectivo. El FPGA **hereda la confianza de la
omisión del OEM**, no de una decisión activa.

Otros campos que consume `nt!Iommu*`/HAL:
- **DMAR flag `DMA_CTRL_PLATFORM_OPT_IN` (bit 2)**: sin él, Kernel DMA Protection
  ni se arma.
- **RMRR** (Reserved Memory Region Reporting): regiones identity-mapped en boot
  para ciertos dispositivos; un RMRR más amplio de lo necesario es una ventana
  legítima-por-tabla.
- **ATSR** (Root Port ATS Capability Reporting): qué root ports permiten ATS.
- **Slot Capabilities (SLTCAP)**: hot-plug-capable y slot físico expuesto → más
  sospecha.

La clasificación es **topológica, no de identidad**.

---

## 7. El invariante de comportamiento

> **Un cheat de lectura DMA, por definición, tiene que leer regiones que no le
> corresponden; esa es la firma que ningún spoofing elimina.**

El fingerprinting de identidad (§3) puede clonarse al límite. El comportamiento no:
- Un NIC legítimo hace DMA acotado a sus anillos de descriptores (Tx/Rx) en
  regiones que *su propio driver le asignó*.
- Un dispositivo de lectura hace MRds contra rangos físicos amplios y cambiantes
  que *ningún driver le asignó*.

Con IOMMU activo, esos accesos "fuera de dominio" son exactamente lo que se
registra como fault (§5). Con pass-through (§4, TT=2) no hay fault — pero entonces
el invariante se detecta por **ausencia de side-effects** (§9.3): un dispositivo
que se declara NIC y hace DMA sin generar tráfico de red real, interrupciones ni
transiciones de energía coherentes es anómalo. Identidad dice "NIC"; comportamiento
dice "nada de lo que un NIC hace".

---

## 8. Telemetría en el kernel: callbacks oficiales

Mecanismos **documentados y cooperativos** — el kernel invita a cada evento; no se
parchea ni se toca estructura no documentada. Todos a `PASSIVE_LEVEL`; el binario
debe ir firmado + `/INTEGRITYCHECK` o el registro da `STATUS_ACCESS_DENIED`.

### 8.1 `ObRegisterCallbacks` — mediación de handles
Pre/post de cada create/duplicate de handle sobre `PsProcessType`/`PsThreadType`,
en el contexto del solicitante. En el pre-op puedes **recortar bits del
`DesiredAccess`** antes de que el handle exista (p. ej. retirar `PROCESS_VM_READ`
contra un proceso tutelado). No deniega — devuelve un handle con menos derechos.

Reglas de estabilidad: ignorar `Info->KernelHandle`; no actuar sobre el caso
"proceso se abre a sí mismo" ni sobre solicitantes legítimos; **trabajo mínimo**
(nada de I/O ni bloqueos — estás en el camino caliente de cada apertura de handle).
Registro con `OB_CALLBACK_REGISTRATION` (altitud única); unload con
`ObUnRegisterCallbacks`.

```c
OB_PREOP_CALLBACK_STATUS
PreOpProcess(PVOID Ctx, POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(Ctx);
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;
    if (PsGetProcessId((PEPROCESS)Info->Object) != g_ProtectedPid)
        return OB_PREOP_SUCCESS;
    ACCESS_MASK* pAccess =
        (Info->Operation == OB_OPERATION_HANDLE_CREATE)
          ? &Info->Parameters->CreateHandleInformation.DesiredAccess
          : &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    // Inspeccionar / retirar bits sobre *pAccess; encolar telemetría a worker.
    return OB_PREOP_SUCCESS;
}
```

### 8.2 `PsSetCreateProcessNotifyRoutineEx` — ciclo de vida de proceso
Invocada en cada creación/terminación. `CreateInfo != NULL` → creación (con
`ImageFileName`, `CommandLine`, `ParentProcessId`, `CreatingThreadId`); `NULL` →
salida. **Veto**: asignar `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`
aborta la creación — mecanismo legítimo para impedir un binario en lista negra.

```c
VOID CreateProcessNotifyEx(PEPROCESS Proc, HANDLE Pid, PPS_CREATE_NOTIFY_INFO Info) {
    if (Info == NULL) { /* Pid terminó */ return; }
    // Info->ImageFileName / CommandLine válidos SOLO durante la llamada: copiar
    // con ExAllocatePool2 + tag si se procesan en worker. Nunca retener punteros.
    // if (EsMalicioso(Info)) Info->CreationStatus = STATUS_ACCESS_DENIED;
}
// DriverEntry:  PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
// DriverUnload: PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
```
Protege el unload con rundown (`ExAcquireRundownProtection` /
`ExWaitForRundownProtectionRelease`) para no liberar pool con callbacks en vuelo.

### 8.3 Hermanos
- `PsSetLoadImageNotifyRoutine`: cada carga de imagen (DLL/driver/EXE) con
  `FullImageName` y base. Sensor de **BYOVD** cruzado con la blocklist HVCI.
- `PsSetCreateThreadNotifyRoutineEx`: creación de hilos; caza hilos remotos
  (inyección).

---

## 9. ETW: observación sin Ring 0

### 9.1 Decisión arquitectónica
- **Driver (Ring 0)** solo para **mediar/vetar en el momento** (recortar access,
  abortar creación, bloquear I/O).
- **Servicio ETW (Ring 3)** para **observar**. La mayor parte de la telemetría no
  necesita kernel; cada línea en Ring 0 es superficie de inestabilidad. Un EDR
  maduro ≈ 80% consumidor ETW + 20% driver de enforcement.

### 9.2 Anatomía de la suscripción
`StartTrace` (sesión real-time) → `EnableTraceEx2` (por GUID, con nivel y
**máscara de keywords** para pedir solo lo que se consume) → `OpenTrace` +
`ProcessTrace` (bombea el `EventRecordCallback`) → **TDH** (`TdhGetEventInformation`
/`TdhGetProperty`) para el esquema y campos por nombre. Implementación en
`src_etw_consumer/`.

Providers (confirmar GUID/keywords en la build con `logman query providers`):

| Provider | GUID |
|---|---|
| Microsoft-Windows-Kernel-Process | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` |
| Microsoft-Windows-Kernel-Network | `7DD42A49-5329-4832-8DFD-43D979153A88` |
| Microsoft-Windows-Kernel-File | `EDD08927-9CC4-4E65-B970-C2560FB5C289` |
| Microsoft-Windows-Threat-Intelligence | (requiere proceso PPL para consumir) |

> No existe un provider "DMA fault" público con GUID citable; la pila VT-d es
> soberanía del kernel. Ancla sólida: Kernel-Pnp + canales de seguridad del kernel.
> Resolver GUID y nombres de propiedad del payload en la propia build.

### 9.3 Rendimiento y robustez
- **Filtra en el origen** (keyword/level, scope filters por PID/imagen), no en el
  callback. Cada evento que cruza a user-mode cuesta.
- **El callback no puede retrasarse**: si se bloquea, la sesión pierde eventos
  (`EventsLost`). Parsea lo mínimo con TDH, copia a cola, correla en otro hilo.
- **Driver como productor**: `TraceLogging` en kernel (`TraceLoggingRegister/Write/
  Unregister`) emite la telemetría del enforcement por el mismo bus ETW que
  consume el servicio — un pipeline único kernel+user, sin IOCTLs a mano.

### 9.4 Cross-view cuando el IOMMU ciega (pass-through)
TT=2 ⇒ sin faults ⇒ ETW de faults ciego. Detección por **ausencia de
side-effects**, cruzando providers:
- **Kernel-Network / contadores Network Interface**: devnode clase Net presente y
  en D0 pero sin miniport NDIS enlazado o Tx/Rx ≈ 0 sostenido.
- **Kernel-Pnp**: ¿bindeó un function driver real?
- **Kernel-Power**: transiciones D-state incoherentes con la supuesta función.
- **WHEA-Logger**: pico de correctables PCIe en el root port del dispositivo.
- El snapshot estático (`iommu_audit.js`) además detecta TT=2 **directamente**.

---

## 10. Minifilters y WFP (visión general)

Las dos plataformas de filtrado soportadas, basadas en **altitud** (orden
determinista entre filtros) y en callbacks pre/post — nunca en parcheo.

- **Minifilters (FltMgr)**: `FltRegisterFilter` (array de callbacks por
  `IRP_MJ_*`) + `FltStartFiltering`; se adjuntan a volúmenes por instancia.
  Auditoría de I/O de archivos: `IRP_MJ_CREATE`, `WRITE`, `SET_INFORMATION`
  (rename/delete). Buenas prácticas: `FltGetFileNameInformation`, contextos con
  `FltAllocateContext` + pool tags, manejo de reparse, no bloquear.
- **WFP (Windows Filtering Platform)**: gestión en user-mode (`FWPM_*`: engine,
  sublayers, filters, conditions) + **callout drivers** en kernel (`FwpsCalloutRegister`,
  `classifyFn`/`notifyFn`). Capas: ALE (autorización de conexión — da eventos
  atribuidos a proceso en `FWPM_LAYER_ALE_AUTH_CONNECT_V4`), transport, stream.
  Inspección segura: permit/block/continue; nunca bloquear indefinidamente.
  Enlaza con §9.4: un "NIC" con cero conexiones observadas por WFP es anómalo.

> Nota de alcance: cubierto a nivel de visión general; profundizar en una sesión
> dedicada antes de implementar.

---

## 11. Catálogo de asserts de detección

Para adversary emulation (casos unitarios sobre dispositivos sintéticos):

| ID | Assert (dispara alerta cuando…) | Fuente |
|----|----|----|
| 1a | Plataforma sin `DMA_CTRL_PLATFORM_OPT_IN` → defensa DMA apagada | DMAR |
| 1b | RMRR más amplio de lo que el tipo de dispositivo necesita | DMAR |
| 1c | Dispositivo "NIC simple" con ATS habilitado / en ATSR | config + DMAR |
| 1d | Dispositivo DMA-capaz en puerto sin `DmaProperty`/`ExternalFacingPort` **y** dominio amplio/pass-through | `_DSD` + VT-d |
| 2a | DSN=0 u OUI(DSN) ≠ OUI(Vendor ID) | Ext. caps |
| 2b | AER con contadores a cero bajo carga / sin reacción a error | Ext. caps (prueba activa) |
| 2c | Latencia ASPM medida ≠ declarada | Link caps (prueba activa) |
| 2d | Cadena de Ext. caps ≠ golden reference de ese VEN/DEV/REV | Ext. caps |
| 3a | Clase Net + Tx/Rx≈0 sostenido + sin miniport NDIS | ETW Network/Pnp |
| 3b | Sin transiciones D-state coherentes con la función | ETW Power |
| 3c | Pico de correctables WHEA en el root port | ETW WHEA |
| V1 | TT=2 (pass-through) en un dispositivo que no debería | `iommu_audit.js` |
| V2 | Bytes totales mapeados por dominio saltan a escala GB | `iommu_audit.js` |
| V3 | SLPTPTR/DID/RTADDR cambian respecto al baseline | `iommu_audit.js` |
| V4 | Fault cuyo BDF no corresponde a ningún devnode presente | ETW + SetupAPI |

**Detección de alta confianza = intersección**, no señal suelta. Las anomalías se
apilan y ningún FPGA las elimina todas sin dejar de hacer su trabajo.

---

## 12. Aislamiento por hardware y límites (VBS/VTL)

- **HVCI** (W^X en kernel vía SLAT/EPT): el hipervisor en VTL1 impide páginas
  kernel simultáneamente escribibles y ejecutables → mata la inyección/parcheo de
  código en Ring 0, empuja al adversario a data-only (más detectable).
- **Kernel DMA Protection / IOMMU**: acorrala por dominio *si está activo y bien
  granulado*. Falla por: `DmaProperty` no puesto (§6), IOMMU desactivado en BIOS,
  dominios compartidos/demasiado amplios, confianza por identidad mal concedida.
- **IOMMU / VT-d DMA remapping**: second-level page tables por dominio; auditar su
  integridad (§4.3).

**Límite de todo driver/script en VTL0**: es tan confiable como él mismo frente a
un adversario Ring-0 paralelo. El `iommu_audit.js` y el consumidor ETW son **capas**
de defensa, no la raíz de confianza. La medición blindada vive en **VTL1** (VBS),
por debajo de donde vive el adversario — esa asimetría es la fortaleza del diseño,
no un estorbo.

---

*Documento de investigación defensiva. Todo el contenido se orienta a detección,
auditoría de integridad y telemetría. Los mecanismos de ataque se describen al
nivel necesario para derivar firmas e invariantes, no para su ejecución.*
