#pragma once
#include "types.h"

// Pipeline de correlación: {BDF, IOVA} -> devnode PnP -> postura DMA + fingerprint.
// Dado un FaultEvent, resuelve el dispositivo físico y decide si emite alerta.
namespace correlation {

struct DeviceContext {
    bool        found       = false;
    wchar_t     instanceId[256] = L"";
    wchar_t     hardwareId[256] = L""; // PCI\VEN_xxxx&DEV_xxxx...  (fingerprint)
    uint32_t    dmaPolicy   = 0;       // postura DMA remapping (ver .cpp: verificar clave)
    bool        dmaPolicyKnown = false;
};

// Resuelve el devnode a partir del BDF del evento.
DeviceContext resolveByBdf(uint8_t bus, uint8_t dev, uint8_t func);

// Entrada del pipeline: correlaciona y, si procede, emite alerta.
void correlate(const FaultEvent& ev);

// Utilidad de descubrimiento: vuelca TODAS las claves de propiedad de un
// devnode, para localizar la clave real de postura DMA en TU build.
void enumerateProperties(uint8_t bus, uint8_t dev, uint8_t func);

} // namespace correlation
