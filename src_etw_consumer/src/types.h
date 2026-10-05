#pragma once
#include <cstdint>

// Tuple normalizado que produce el consumidor ETW y consume la correlación.
// El Source ID (SID) del fault VT-d es un Requester ID de 16 bits:
//   bits [15:8] = bus, [7:3] = device, [2:0] = function.
struct FaultEvent {
    uint16_t segment      = 0;   // segmento/dominio PCI (normalmente 0)
    uint8_t  bus          = 0;
    uint8_t  dev          = 0;
    uint8_t  func         = 0;
    uint64_t iova         = 0;   // dirección (IOVA) que disparó el bloqueo
    uint8_t  access       = 0;   // 0 = read, 1 = write
    uint64_t timestampQpc = 0;

    static FaultEvent fromSid(uint16_t sid, uint64_t iova, uint8_t acc, uint64_t ts) {
        FaultEvent e;
        e.bus  = static_cast<uint8_t>((sid >> 8) & 0xFF);
        e.dev  = static_cast<uint8_t>((sid >> 3) & 0x1F);
        e.func = static_cast<uint8_t>(sid & 0x07);
        e.iova = iova; e.access = acc; e.timestampQpc = ts;
        return e;
    }
};
