# Conceptos 101 — explicado sin bajo nivel

Esta guía es para cualquiera que aterrice en el proyecto **sin experiencia en
kernel, ensamblador ni interioridades de Windows**. Cero código. Solo analogías
para entender **qué defendemos y por qué**.

El proyecto construye piezas de un **EDR** (Endpoint Detection and Response): un
sistema que vigila un ordenador desde dentro y avisa cuando algo se comporta como
un intruso. Aquí nos centramos en dos trucos clásicos que usan los atacantes
avanzados para pasar desapercibidos, y en cómo los cazamos.

---

## El edificio de alta seguridad (el modelo mental)

Imagina que el ordenador es un **edificio de alta seguridad**:

- Las **plantas bajas** (Ring 3) son las oficinas normales: ahí viven los
  programas del usuario.
- El **sótano de máquinas** (Ring 0) es donde está la fontanería crítica: el
  núcleo del sistema (*kernel*). Quien controla el sótano, controla el edificio.
- En la **recepción** hay guardias (el EDR) que observan quién entra, quién sale
  y quién hace cosas raras.

Los atacantes quieren llegar al sótano y moverse por él **sin que la recepción
los apunte en ningún sitio**. Las dos técnicas de abajo son dos formas de
conseguirlo.

---

## 1. BYOVD — "trae tu propio contratista con llave maestra"

**BYOVD** = *Bring Your Own Vulnerable Driver* ("trae tu propio driver
vulnerable").

Un **driver** es un contratista con **pase oficial** para bajar al sótano: el
sistema solo deja entrar a contratistas cuyo pase está **firmado** por un
fabricante reconocido. Hasta aquí, bien: es como exigir un carnet acreditado.

El problema: algunos contratistas con pase válido son **descuidados**. Tienen una
llave maestra y, si alguien les pide "ábreme esa puerta", la abren **sin
preguntar para qué**. El atacante no necesita falsificar un pase (eso es difícil
y está muy vigilado): simplemente **trae a un contratista acreditado pero
descuidado** —un driver firmado pero vulnerable, como los clásicos `capcom.sys`
o `gdrv.sys`— y lo usa de palanca para abrir cualquier puerta del edificio
(leer o escribir en cualquier parte de la memoria).

La trampa es sutil: el guardia confía en el **pase** (la firma), no en el
**comportamiento**. El contratista es "legítimo", así que nadie se alarma.

**Cómo lo cazamos (en cristiano):**
- Mantenemos una **lista negra de contratistas descuidados conocidos** (el
  catálogo `known_vulnerable.csv`). Si alguien hace entrar a uno, salta la
  alerta.
- Sospechamos de la **procedencia**: un contratista con llave maestra que
  aparece desde un **cajón del usuario** (una carpeta como `Temp` o `Descargas`,
  donde cualquiera puede dejar cosas) en vez de desde el almacén oficial, es
  raro. Un driver `.sys` cargándose desde ahí es señal de alarma.
- La fuerza está en **cruzar señales**: firmado **y** en la lista negra **y**
  desde una ruta rara **y** poco habitual = casi seguro un abuso.

---

## 2. Call-Stack Spoofing — "falsificar el registro de visitantes"

### La pila de llamadas = el libro de visitas de recepción

Cada vez que una parte del programa "llama" a otra, es como un visitante que
**firma en el libro de recepción** al entrar a una sala, y **tacha su firma** al
salir. Ese libro, leído de abajo arriba, cuenta la **cadena de quién llamó a
quién**: "Entró Ana → Ana llamó a Beto → Beto llamó a Carla". Eso es la **pila
de llamadas** (*call stack*).

Cuando algo sospechoso ocurre (por ejemplo, alguien intenta abrir la caja
fuerte), el guardia hace lo obvio: **mira el libro de visitas** para ver quién
está detrás. Si el libro dice "esto lo pidió una rutina de confianza del propio
sistema" (el equivalente a "estaba el conserje echándose una siesta,
`Sleep`"), el guardia se queda tranquilo.

### El truco del atacante

El atacante **falsifica el libro de visitas**: arregla las páginas para que
parezca que quien pidió abrir la caja fuerte fue el conserje de confianza, cuando
en realidad fue él. Así, cuando el guardia mira, ve una cadena **plausible y
aburrida** y no se alarma.

### Por qué la falsificación siempre deja huellas

Un libro de visitas **de verdad** cumple ciertas reglas que un libro **forjado**
casi nunca respeta a la vez. Nuestro detector comprueba cinco (las 5
comprobaciones del `stack_spoof_detector`):

1. **¿La firma remite a una oficina real del edificio?**
   Cada entrada del libro debería apuntar a una sala que existe en los planos
   oficiales (*código respaldado por un archivo en disco*). Si apunta a un
   cuartucho montado a toda prisa en memoria (código "privado", sin plano), es
   falso. → *ReturnInModule*.
2. **¿La sala está en el índice oficial del edificio?**
   Las salas reales están registradas en el directorio del edificio (*información
   de "unwind"*). Una entrada que apunta a un punto **sin registrar** delata una
   página metida con calzador. → *UnwindCoherent*.
3. **¿El libro está en el atril de recepción, o en una mesa cualquiera?**
   El libro auténtico vive en un sitio fijo y acotado (los **límites de pila** que
   el sistema asigna a cada hilo, guardados en el *TEB*). Los atacantes suelen
   forjar su libro en **cualquier mesa que encuentren** (memoria reservada aparte).
   Si el "puntero" al libro cae fuera de ese atril, es sintético. → *TebBounds*.
4. **¿Cada firma viene precedida de una invitación real?**
   En el edificio, nadie entra a una sala sin que alguien **haya hecho la llamada**
   justo antes (una instrucción `call`). Si una firma aparece sin esa invitación
   previa, alguien la escribió a mano. → *CallPreceded*.
5. **¿El libro empieza por la puerta principal?**
   Toda cadena real arranca en la **entrada del edificio** (el arranque del hilo:
   `RtlUserThreadStart`). Un libro que no empieza ahí está recortado o inventado.
   → *Termination*.

Ninguna comprobación aislada es una prueba definitiva, pero **varias fallando a
la vez** es casi imposible en un programa honesto: ahí es donde desenmascaramos
al intruso.

---

## ¿Y el tercer vector (DKOM)?

Hay un tercero, **DKOM**, que es "tachar tu propio nombre del libro de inquilinos
del edificio" para que no aparezcas en la lista de procesos. Lo tratamos en
`Software_Tampering_Detection.md`; la idea clave de su detección es la misma
filosofía: aunque borres tu nombre de una lista, **sigues necesitando usar los
ascensores** (hilos en el planificador de la CPU), y eso deja rastro en **otra**
lista que no tocaste.

---

## Para seguir

- `Software_Tampering_Detection.md` — la versión técnica (telemetría, ETW,
  callbacks, IoCs concretos) de todo lo de arriba.
- `Architecture_and_Theory.md` — la rama de hardware del proyecto (ataques DMA).
- `README.md` → sección **Rampa de entrada** — cómo compilar y correr los tests.
