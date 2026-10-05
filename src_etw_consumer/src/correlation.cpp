#include "correlation.h"

#include <windows.h>
#include <initguid.h>     // instancia los DEVPROPKEY de devpkey.h
#include <setupapi.h>
#include <devpkey.h>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")

namespace {

// -----------------------------------------------------------------------------
// Clave de postura de DMA remapping por dispositivo.
//
// HONESTIDAD: a la fecha de este PoC NO está confirmado que exista un DEVPKEY
// documentado y estable llamado DEVPKEY_Device_DmaRemappingPolicy con un
// {GUID,PID} citable. NO lo inventes. El camino robusto:
//   1) ejecuta `edrsvc enumprops <bus> <dev> <func>` (enumerateProperties)
//   2) localiza en el volcado la clave DMA de tu build
//   3) pégala aquí con DEFINE_DEVPROPKEY y actívala.
// Mientras tanto, la correlación reporta la postura como "desconocida" en
// lugar de leer una clave fabricada.
//
// DEFINE_DEVPROPKEY(DEVPKEY_Device_DmaRemappingPolicy,
//     0x........, 0x...., 0x...., 0x.., 0x.., 0x.., 0x.., 0x.., 0x.., 0x.., 0x.., PID);
// -----------------------------------------------------------------------------

bool readU32(HDEVINFO h, SP_DEVINFO_DATA& d, const DEVPROPKEY& key, uint32_t& out) {
    DEVPROPTYPE t = 0;
    return SetupDiGetDevicePropertyW(h, &d, &key, &t,
               reinterpret_cast<PBYTE>(&out), sizeof(out), nullptr, 0)
           && t == DEVPROP_TYPE_UINT32;
}

bool readStr(HDEVINFO h, SP_DEVINFO_DATA& d, const DEVPROPKEY& key,
             wchar_t* buf, DWORD cb) {
    DEVPROPTYPE t = 0;
    return SetupDiGetDevicePropertyW(h, &d, &key, &t,
               reinterpret_cast<PBYTE>(buf), cb, nullptr, 0)
           && (t == DEVPROP_TYPE_STRING || t == DEVPROP_TYPE_STRING_LIST);
}

} // namespace

namespace correlation {

DeviceContext resolveByBdf(uint8_t bus, uint8_t dev, uint8_t func) {
    DeviceContext ctx;
    // Sólo dispositivos PCI presentes.
    HDEVINFO h = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr,
                                      DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (h == INVALID_HANDLE_VALUE) return ctx;

    SP_DEVINFO_DATA d{}; d.cbSize = sizeof(d);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &d); ++i) {
        uint32_t busNo = 0, addr = 0;
        if (!readU32(h, d, DEVPKEY_Device_BusNumber, busNo)) continue;
        if (!readU32(h, d, DEVPKEY_Device_Address,  addr))  continue;

        // En PCI: Address = (DeviceNumber << 16) | FunctionNumber.
        uint8_t dv = static_cast<uint8_t>((addr >> 16) & 0xFFFF);
        uint8_t fn = static_cast<uint8_t>(addr & 0xFFFF);
        if (busNo != bus || dv != dev || fn != func) continue;

        ctx.found = true;
        SetupDiGetDeviceInstanceIdW(h, &d, ctx.instanceId,
                                    _countof(ctx.instanceId), nullptr);
        readStr(h, d, DEVPKEY_Device_HardwareIds,
                ctx.hardwareId, sizeof(ctx.hardwareId));

        // Postura DMA: activar cuando la clave real esté confirmada (ver arriba).
        // if (readU32(h, d, DEVPKEY_Device_DmaRemappingPolicy, ctx.dmaPolicy))
        //     ctx.dmaPolicyKnown = true;
        break;
    }
    SetupDiDestroyDeviceInfoList(h);
    return ctx;
}

void correlate(const FaultEvent& ev) {
    DeviceContext ctx = resolveByBdf(ev.bus, ev.dev, ev.func);

    wprintf(L"[FAULT] BDF %02x:%02x.%u  IOVA 0x%llx  %s\n",
            ev.bus, ev.dev, ev.func,
            static_cast<unsigned long long>(ev.iova),
            ev.access ? L"W" : L"R");

    if (!ctx.found) {
        // Un fault cuyo BDF NO corresponde a ningún devnode presente es, de por
        // sí, una anomalía fuerte (dispositivo oculto / desaparecido del árbol).
        wprintf(L"  -> [!! ALERTA] BDF sin devnode PnP presente\n");
        return;
    }

    wprintf(L"  -> devnode : %s\n", ctx.instanceId);
    wprintf(L"  -> hwid    : %s\n", ctx.hardwareId);
    if (ctx.dmaPolicyKnown)
        wprintf(L"  -> DMA pol : %u\n", ctx.dmaPolicy);
    else
        wprintf(L"  -> DMA pol : (clave no confirmada en esta build; ver enumprops)\n");

    // --- Lógica de alerta (esqueleto) ---------------------------------------
    // La señal fuerte NO es un fault aislado, es el PATRÓN. Aquí cruzarías:
    //   * tasa sostenida de faults del mismo BDF (ventana temporal)
    //   * cobertura de IOVAs barriendo rangos amplios
    //   * identidad declarada (hwid VEN/DEV) incoherente con el comportamiento
    //   * postura DMA que debería acorralar y no lo hace
    // -> EmitAlert(ctx, pattern) cuando se cruce el umbral.
}

void enumerateProperties(uint8_t bus, uint8_t dev, uint8_t func) {
    HDEVINFO h = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr,
                                      DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (h == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA d{}; d.cbSize = sizeof(d);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(h, i, &d); ++i) {
        uint32_t busNo = 0, addr = 0;
        if (!readU32(h, d, DEVPKEY_Device_BusNumber, busNo)) continue;
        if (!readU32(h, d, DEVPKEY_Device_Address,  addr))  continue;
        if (busNo != bus ||
            ((addr >> 16) & 0xFFFF) != dev || (addr & 0xFFFF) != func) continue;

        DWORD n = 0;
        SetupDiGetDevicePropertyKeys(h, &d, nullptr, 0, &n, 0);
        if (!n) break;
        auto* keys = new DEVPROPKEY[n];
        if (SetupDiGetDevicePropertyKeys(h, &d, keys, n, &n, 0)) {
            wprintf(L"Claves de propiedad del devnode (%u):\n", n);
            for (DWORD k = 0; k < n; ++k)
                wprintf(L"  {%08lx-...}  PID %lu\n",
                        keys[k].fmtid.Data1, keys[k].pid);
        }
        delete[] keys;
        break;
    }
    SetupDiDestroyDeviceInfoList(h);
}

} // namespace correlation
