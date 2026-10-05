# Detección de manipulación interna del SO — BYOVD, DKOM y Call-Stack Spoofing

**Investigación defensiva (blue team).** Telemetría y reglas de endurecimiento
para **detectar y bloquear** tres familias de manipulación del sistema operativo
por software (Ring 0 / Ring 3).

> Alcance estrictamente defensivo. La mecánica de ataque se describe **al nivel
> conceptual justo para derivar el invariante de detección**, no como recetario
> de explotación: este documento no incluye código de exploit, IOCTLs, offsets,
> ni secuencias para construir primitivas o frames falsificados. El valor está
> en la telemetría, los invariantes y el hardening.

El hilo conductor es el mismo del handbook de DMA: cada técnica, por definición,
**tiene que dejar un rastro** que su propia naturaleza no puede borrar. Ese
rastro es lo que instrumentamos.

---

## 1. BYOVD — Bring Your Own Vulnerable Driver

### Mecánica (conceptual)
Un driver de terceros válidamente firmado carga aunque haya DSE/HVCI, porque la
firma es legítima. El problema es que ciertos drivers comerciales **exponen
operaciones privilegiadas de memoria** —mapeo de memoria física (`MmMapIoSpace`)
o copias masivas tipo `memcpy`— a través de un *device object* cuyo dispatch de
IOCTL no comprueba de forma significativa quién llama. El atacante no ejecuta su
propio código en kernel: le pide al driver firmado que realice la operación por
él, obteniendo un primitivo de lectura/escritura de memoria que luego usa para
tocar estructuras del kernel.

### Invariante
Un binario **firmado pero raro**, de un vendor sin relación con el host, aparece
—a menudo desde una ruta escribible por el usuario— justo antes de actividad
privilegiada, y su device recibe `DeviceIoControl` de procesos que no tienen por
qué hablarle.

### Telemetría / detección

| Fuente | Qué aporta | Señal |
|---|---|---|
| `PsSetLoadImageNotifyRoutine` (callback kernel) | cada carga de imagen incl. drivers: ruta, base, flags | driver fuera de baseline / hash o nombre en lista de vulnerables |
| ETW image-load (Ring 3) / Sysmon EID 6 | carga de driver sin driver propio | ruta en directorio escribible por usuario; firmante ajeno al host |
| ETW/registro: creación de servicio | servicio con `start type = kernel` | servicio-driver creado y arrancado *just-in-time* por un proceso no-instalador |

Alta confianza por **intersección**: (firmado) ∧ (hash/nombre en lista de
vulnerables — semilla LOLDrivers + blocklist de Microsoft, ampliada con la
propia) ∧ (baja prevalencia / ruta anómala / firmante no relacionado).

### Hardening
WDAC / App Control allow-listing de drivers por publisher o hash; mantener una
lista **propia** ampliada de hashes vulnerables; vigilar la creación de
servicios de tipo kernel.

---

## 2. DKOM — Direct Kernel Object Manipulation

### Mecánica (conceptual)
Con escritura en Ring 0, el actor edita objetos del kernel directamente en
memoria en vez de pasar por APIs. Caso de libro (técnica pública desde ~2005):
desenlazar la entrada de un proceso de la lista doblemente enlazada
`ActiveProcessLinks` dentro de `_EPROCESS`, de modo que los enumeradores que
recorren esa lista (Task Manager vía `NtQuerySystemInformation`) no lo vean.

### Invariante
Un proceso oculto **sigue necesitando hilos planificables** para ejecutarse, y
el scheduler y las tablas de hilos/handles **no son la misma lista** que se
manipuló. De ahí la detección por *cross-view*.

### Telemetría / detección
- **Fuente de verdad propia:** `PsSetCreateProcessNotifyRoutineEx` +
  `PsSetCreateThreadNotifyRoutineEx` registran el nacimiento autoritativo de
  procesos/hilos **en el origen**. Un proceso que tuvo callback de creación pero
  está ausente de un recorrido posterior de `ActiveProcessLinks` = fantasma. No
  pueden desenlazarse de un callback que ya disparó.
- **Cruce de vistas:** lista de `NtQuerySystemInformation` (procesos) vs.
  propietarios en `SystemHandleInformation` (handles) vs. propietarios de hilos
  (`_ETHREAD` → `_EPROCESS`). Un `_EPROCESS` referenciado por hilos/handles pero
  ausente de la lista de procesos es la discrepancia que delata.
- Comparar también `PspCidTable` (tabla PID/handle) frente a
  `ActiveProcessLinks`.

Desde user-mode puro solo se logra un cross-view débil (Toolhelp/WMI vs.
enumeración de handles); el robusto quiere los callbacks de kernel.

---

## 3. Thread Call-Stack Spoofing

### Mecánica (conceptual)
Cuando un hilo hace un syscall o una API sensible, el EDR *desenrolla* la pila de
usuario para ver quién llamó. El spoofing dispone el contenido de la pila y los
frames para que el unwind produzca una cadena benigna y plausible (p. ej. que
parezca una espera dentro de una DLL del sistema). Una pila fabricada **rompe
invariantes del ABI de x64** que la real respeta.

### Invariante / IoCs a nivel de memoria
- **Return address en memoria no respaldada por disco** (`MEM_PRIVATE`/RWX en vez
  de dentro de un módulo mapeado desde imagen) → código sin backing.
- **Sin unwind info:** la dirección de retorno cae en una función sin
  `RUNTIME_FUNCTION` correspondiente en `.pdata` → unwind irreconciliable con el
  oficial.
- **RSP fuera de los límites de pila** del hilo declarados en el TEB
  (`StackBase`/`StackLimit`), o aparición de varias pilas.
- **El byte previo al return target no es una instrucción `call`** (chequeo
  call-preceded).
- **La cadena no termina** en el thunk de arranque esperado
  (`RtlUserThreadStart` / `BaseThreadInitThunk`).
- **Start address del hilo** en memoria no respaldada; o `WaitReason`
  incoherente con el frame declarado.

### Telemetría / detección
Exige *stack walk* en el momento del evento sensible. Vía práctica desde ETW:
activar captura de pila con `EVENT_ENABLE_PROPERTY_STACK_TRACE` en
`EnableTraceEx2` (da pilas kernel+usuario de los eventos), o el provider
Threat-Intelligence; luego validar cada frame contra (rangos de módulos
cargados) + (unwind data) + (límites de pila del TEB).

---

## Hoja de ruta de implementación

Orden por tractabilidad desde el consumidor Ring-3 actual:

1. **BYOVD — carga de drivers (PRIMERO).** Observable desde user-mode, sin driver
   propio; reutiliza el extractor *schema-driven* del consumidor ETW. Módulo
   `byovd_detector` (ver `src_etw_consumer/src/byovd_detector.*`): puntúa una
   carga de imagen contra el catálogo `byovd/known_vulnerable.csv` + heurística
   de ruta. **Cableado a image-load en vivo** vía `ImageLoadConsumer` (modo
   `edrsvc imgwatch`): suscribe Microsoft-Windows-Kernel-Process (keyword IMAGE,
   Event Id 5), extrae ruta + PID por TDH, infiere modo kernel (`.sys` / System
   PID 4) y evalúa. Provider/keyword/Event Id y el nombre de la propiedad de ruta
   son *defaults* confirmables en la build.
2. **Call-stack spoofing.** La sesión de `imgwatch` instrumenta
   `EVENT_ENABLE_PROPERTY_STACK_TRACE` y cuenta los frames adjuntos. La **lógica
   de validación está implementada** en `stack_spoof_detector` (las 5
   comprobaciones: ReturnInModule, UnwindCoherent, TebBounds, CallPreceded,
   Termination), con lógica pura inyectable (`IStackEnv`) y **tests unitarios**
   con frames sintéticos ejecutados en CI (CTest). Falta el entorno en vivo
   (Win32): resolver cada frame con `VirtualQuery` (MEM_IMAGE vs privada),
   `RtlLookupFunctionEntry` (`.pdata`), rango de los thunks de arranque y lectura
   del byte previo para el call-preceded; y alimentar el detector con las pilas
   capturadas por ETW.
3. **DKOM.** Requiere los callbacks de kernel para una fuente de verdad robusta;
   va cuando añadamos el componente de kernel.

---

## Referencias
- Microsoft, *Vulnerable and malicious driver blocklist* (HVCI / App Control).
- Proyecto comunitario **LOLDrivers** (catálogo de drivers vulnerables/maliciosos).
- Windows ETW: `EnableTraceEx2`, `EVENT_ENABLE_PROPERTY_STACK_TRACE`, TDH.
- Kernel callbacks: `PsSetLoadImageNotifyRoutine`,
  `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutineEx`.
- Windows Internals (Russinovich et al.): `_EPROCESS`, `ActiveProcessLinks`,
  `_ETHREAD`, `PspCidTable`; ABI x64 y datos de unwind (`.pdata` /
  `RUNTIME_FUNCTION`).
