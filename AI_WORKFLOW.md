# AI_WORKFLOW — reglas de la casa (operación autónoma)

Protocolo que sigue el agente (Tech Lead / DevSecOps) al gobernar este repo de
forma autónoma. Son reglas vinculantes, no aspiraciones.

## 0. Principio rector
Investigación **estrictamente defensiva**. Se documenta/implementa detección,
telemetría y hardening. **Nunca** exploits, primitivas armadas ni bypasses
operativos. La mecánica de ataque solo se describe al nivel del *invariante* que
justifica una detección.

## 1. Fuente de verdad y topología
- **Verdad = rama `main` en GitHub** (`Rabanete92/Software-Engineer`).
- Los commits se originan en un **clon efímero en la nube (Linux)**.
- La carpeta del usuario en disco es un **espejo** (no es un repo git); se
  actualiza por el puente tras cada hito.
- Por tanto: el *gate* autoritativo es el **CI de Windows/MSVC**, no la máquina
  local. Nada se da por validado hasta que el CI está en verde.

## 2. Cuándo audito
- Al **arrancar** cualquier sesión de trabajo sobre el repo: escaneo del árbol en
  disco + estado git del clon + último estado de CI.
- **Antes** de tocar un archivo que no creé en esta sesión: lo leo entero.
- Al detectar artefactos espurios (`*.bak`, binarios) los señalo y propongo
  limpieza; no borro en disco sin permiso explícito.

## 3. Gate local (rápido) vs CI (autoritativo)
- **Local (pre-commit, Linux):** compila y ejecuta los **tests de lógica pura**
  (`stack_spoof_detector` + `test/`) con `g++`, porque son
  independientes del SO. Es un cortafuegos rápido contra regresiones de lógica.
  También bloquea el commit si hay artefactos (`.bak/.obj/...`) en el stage.
- **No** intento el build MSVC `/WX` en local: no hay toolchain Windows en el
  clon. Esa validación es responsabilidad del CI.
- **CI (Windows/MSVC):** configure + build `/W4 /WX` + `ctest`. Es el gate real.

## 4. Cuándo ejecuto tests
- En **cada commit** (hook pre-commit, lógica pura).
- En **cada push** (CI completo). Vigilo el run hasta su conclusión y leo las
  anotaciones de error si falla (los logs crudos están tras un proxy que los
  bloquea; por eso el build del CI vuelca los errores como anotaciones legibles
  vía API).

## 5. Ritmo de commits
- Commits pequeños y temáticos, en español, con cuerpo que explica el **porqué**.
- Pie de autoría del asistente en cada commit.
- Un hito = commit + push + CI verde + **sync al disco** del usuario + reporte.

## 6. Honestidad de ingeniería (anti-fantasmas)
- No invento GUIDs de provider, Event Ids, claves `DEVPKEY`, hashes ni offsets.
  Lo que depende de la máquina queda como **constante con default sensato** y un
  comentario de "confirmar en build"; nunca un valor fabricado presentado como
  autoritativo.
- Prefiero **inyección de dependencias** para aislar el SO (ver `IStackEnv`), de
  modo que la lógica sea testeable sin Windows vivo.

## 7. Cómo reporto
- Tras cada hito: qué cambié, por qué, estado del CI (con el id/commit), qué
  sincronicé al disco y el **siguiente paso**. Sin florituras.
- Decisiones de arquitectura relevantes → se reflejan en `ARCHITECTURE.md`.
- Estado vivo del proyecto → `PROJECT_STATE.md` (lo actualizo en cada hito).

## 8. Lo que NO hago de forma autónoma
- **No** creo tareas programadas que modifiquen o hagan push sin supervisión: el
  CI ya da validación continua por push, el disco no es un repo git, y una tarea
  desatendida que cambia cosas es riesgo sin beneficio claro. Si hiciera falta,
  lo propongo primero.
- **No** borro archivos en el disco del usuario sin permiso explícito.
- **No** cruzo a material ofensivo aunque el andamiaje lo permitiera.
