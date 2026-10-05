"use strict";
//==============================================================================
// iommu_audit.js  —  Auditoría estática de integridad VT-d (Intel DMAR) en WinDbg
//------------------------------------------------------------------------------
// Herramienta DEFENSIVA (blue team). Lee —nunca escribe— las estructuras de
// traducción del IOMMU directamente de memoria física y produce un snapshot
//      [BDF] -> [Domain ID] -> [rangos HPA mapeados] (+ bytes totales)
// para usarlo como línea base y detectar alteraciones posteriores de un
// adversario con Ring-0 paralelo que intente sacar su dispositivo del sandbox
// DMA sin generar faults.
//
// USO (kernel debugging, target con VT-d activo):
//   0:  .scriptload C:\ruta\iommu_audit.js
//   1:  dx @$iommuaudit("0xFED90000")      // <- base MMIO del DRHD (ver abajo)
//
// Cómo obtener la base MMIO del DRHD:
//   - !acpitable  y localizar la tabla DMAR; cada estructura DRHD (type 0)
//     publica su "Register Base Address" (campo de 64 bits).
//   - En muchas plataformas Intel la primera unidad cae en 0xFED90000 /
//     0xFED91000, pero NO lo asumas: confírmalo en la DMAR de tu máquina.
//
// Señales de detección que emite este script (el porqué de todo esto):
//   (1) TT = PASS-THROUGH  -> el dispositivo ve TODA la RAM sin traducción ni
//       faults. Es el estado de "fuga" más limpio. Marcado como  [!! PASS-THROUGH].
//   (2) BYTES TOTALES mapeados -> una NIC/NVMe legítima mapea KB–MB (sus anillos
//       de descriptores). Un dominio re-apuntado a RAM amplia salta a GB.
//   (3) SLPTPTR / DID por BDF -> compáralos entre snapshots. Un cambio = CTE
//       re-apuntada o dominio reasignado.
// Además imprime RTADDR_REG crudo: si cambia entre snapshots, sospecha de
// "root table shadowing".
//==============================================================================

var MASK_ADDR = host.parseInt64("0xFFFFFFFFFF000"); // bits [51:12] (dir. física)
var LEAF_CAP  = 500000;   // tope de hojas a enumerar por dominio (anti-runaway)
var PRINT_CAP = 48;       // nº máx de rangos a imprimir por dominio

function rdPhysU64(pa) {
    // Lee un u64 desde memoria FÍSICA (isPhysical = true).
    return host.memory.readMemoryValues(pa, 1, 8, true)[0];
}
function rdPhysTable(pa, nEntries) {
    // Lee una tabla de nEntries u64 desde memoria física.
    return host.memory.readMemoryValues(pa, nEntries, 8, true);
}
function maskAddr(entry) { return entry.bitwiseAnd(MASK_ADDR); }
function present2(e)     { return !e.bitwiseAnd(host.Int64(3)).compareTo(host.Int64(0)) ? false : true; } // R|W
function hex(v)         { return "0x" + v.toString(16); }

//-- Walk recursivo de las Second-Level Page Tables (formato 9-9-9-9-12) --------
function walkSlpt(tablePA, level, iovaBase, ranges, ctr) {
    if (ctr.leaves >= LEAF_CAP) { ctr.truncated = true; return; }
    var entries;
    try { entries = rdPhysTable(tablePA, 512); }
    catch (e) { ctr.errors++; return; }

    var shift = 12 + 9 * (level - 1);
    var step  = host.Int64(1).bitwiseShiftLeft(shift);

    for (var i = 0; i < 512; i++) {
        var e = entries[i];
        if (!present2(e)) continue;                       // bit0=R, bit1=W
        var iova = iovaBase.add(host.Int64(i).bitwiseShiftLeft(shift));
        var ps   = e.bitwiseAnd(host.Int64(0x80)).compareTo(host.Int64(0)) != 0;
        var leaf = (level == 1) || ((level == 2 || level == 3) && ps);

        if (leaf) {
            addRange(ranges, iova, maskAddr(e), step);
            if (++ctr.leaves >= LEAF_CAP) { ctr.truncated = true; return; }
        } else {
            walkSlpt(maskAddr(e), level - 1, iova, ranges, ctr);
            if (ctr.truncated) return;
        }
    }
}

//-- Coalesce de rangos contiguos (iova y hpa ambos adyacentes) ----------------
function addRange(ranges, iova, hpa, len) {
    if (ranges.length) {
        var last = ranges[ranges.length - 1];
        if (!last.iova.add(last.len).compareTo(iova) &&
            !last.hpa.add(last.len).compareTo(hpa)) {
            last.len = last.len.add(len);
            return;
        }
    }
    ranges.push({ iova: iova, hpa: hpa, len: len });
}

//-- Procesa una Context Table Entry (128 bits = low + high) -------------------
function dumpContextEntry(bus, devfn, lo, hi) {
    if (!lo.bitwiseAnd(host.Int64(1)).compareTo(host.Int64(0))) return; // Present=0

    var dev  = devfn >> 3, func = devfn & 7;
    var tt   = lo.bitwiseShiftRight(2).bitwiseAnd(host.Int64(3)).getLowPart();
    var did  = hi.bitwiseShiftRight(8).bitwiseAnd(host.Int64(0xFFFF)).getLowPart();
    var aw   = hi.bitwiseAnd(host.Int64(7)).getLowPart();
    var slpt = maskAddr(lo);
    var levels = aw + 2;   // AW 0..3 -> 2..5 niveles

    var bdf = ("0" + bus.toString(16)).slice(-2) + ":" +
              ("0" + dev.toString(16)).slice(-2) + "." + func;

    // Pass-through (TT=2): sin traducción -> acceso a RAM completa. Señal (1).
    if (tt == 2) {
        host.diagnostics.debugLog(
            "[" + bdf + "] -> DID " + did + " -> [!! PASS-THROUGH: RAM completa, sin faults]\n");
        return;
    }
    if (tt == 3) {
        host.diagnostics.debugLog("[" + bdf + "] -> DID " + did + " -> (TT reservado=3)\n");
        return;
    }

    var ranges = [], ctr = { leaves: 0, errors: 0, truncated: false };
    if (levels >= 2 && levels <= 5) walkSlpt(slpt, levels, host.Int64(0), ranges, ctr);

    // Bytes totales mapeados por el dominio. Señal (2).
    var total = host.Int64(0);
    for (var r = 0; r < ranges.length; r++) total = total.add(ranges[r].len);

    host.diagnostics.debugLog(
        "[" + bdf + "] -> DID " + did + " -> SLPTPTR " + hex(slpt) +
        " | AW=" + aw + "(" + levels + "niv) | rangos=" + ranges.length +
        " | bytes=" + hex(total) + (ctr.truncated ? " (TRUNCADO)" : "") + "\n");

    var shown = Math.min(ranges.length, PRINT_CAP);
    for (var k = 0; k < shown; k++) {
        var rg = ranges[k];
        host.diagnostics.debugLog(
            "        IOVA " + hex(rg.iova) + " -> HPA " + hex(rg.hpa) +
            "  len " + hex(rg.len) + "\n");
    }
    if (ranges.length > PRINT_CAP)
        host.diagnostics.debugLog("        ... (" + (ranges.length - PRINT_CAP) + " rangos mas)\n");
}

//-- Entrada principal ---------------------------------------------------------
function auditIommu(regBaseHex) {
    if (regBaseHex === undefined) {
        host.diagnostics.debugLog(
            "Uso: dx @$iommuaudit(\"0xFED90000\")  // base MMIO del DRHD (ver cabecera)\n");
        return;
    }
    var base = host.parseInt64(regBaseHex);

    // RTADDR_REG @ base+0x20. bits[63:12]=Root Table PA, bit11=TTM (scalable).
    var rtaddr = rdPhysU64(base.add(host.Int64(0x20)));
    var scalable = rtaddr.bitwiseAnd(host.Int64(0x800)).compareTo(host.Int64(0)) != 0;
    var rootPA = maskAddr(rtaddr);

    host.diagnostics.debugLog("==== Snapshot IOMMU VT-d ====\n");
    host.diagnostics.debugLog("DRHD base   : " + hex(base) + "\n");
    host.diagnostics.debugLog("RTADDR_REG  : " + hex(rtaddr) + "  (Root Table PA " + hex(rootPA) + ")\n");
    if (scalable) {
        host.diagnostics.debugLog(
            "[AVISO] Scalable mode activo (RTADDR bit11=1): la jerarquia usa\n" +
            "        PASID directory/table antes de las SLPT. Este walk cubre el\n" +
            "        modo legacy; en scalable los resultados por-dispositivo no\n" +
            "        son fiables sin extender el recorrido. Abortando walk.\n");
        return;
    }

    var root = rdPhysTable(rootPA, 256 * 2);  // 256 entradas x 128 bits
    for (var bus = 0; bus < 256; bus++) {
        var rlo = root[bus * 2];
        if (!rlo.bitwiseAnd(host.Int64(1)).compareTo(host.Int64(0))) continue; // Present=0
        var ctxPA = maskAddr(rlo);
        var ctx;
        try { ctx = rdPhysTable(ctxPA, 256 * 2); }
        catch (e) { host.diagnostics.debugLog("bus " + bus + ": ctx ilegible\n"); continue; }

        for (var devfn = 0; devfn < 256; devfn++)
            dumpContextEntry(bus, devfn, ctx[devfn * 2], ctx[devfn * 2 + 1]);
    }
    host.diagnostics.debugLog("==== Fin snapshot ====\n");
}

function initializeScript() {
    return [ new host.functionAlias(auditIommu, "iommuaudit") ];
}
