#include "etw_consumer.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>   // calloc / free
#include <climits>   // ULONG_MAX
#include <string.h>  // _wcsicmp
#include <initializer_list>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    const wchar_t* kSessionName = L"EdrDmaWatch";

    // -------------------------------------------------------------------------
    // GUID del/los provider(s). RELLENAR tras resolverlo EN TU BUILD con:
    //     logman query providers | findstr /i "dma pnp device guard"
    // No hay un provider "DMA fault" público y documentado con GUID citable;
    // el ancla sólida es Microsoft-Windows-Kernel-Pnp y los canales de
    // seguridad del kernel. Pega aquí el GUID autoritativo de tu máquina.
    // -------------------------------------------------------------------------
    const GUID kProvider = {};   // {0...0} placeholder: no habilita nada real

    // IDs de evento que consideramos "fallo de traducción DMA". Resolver en la
    // build con `tracerpt` sobre un .etl de muestra, o leyendo
    // EventDescriptor.Id de los eventos vivos. Lista VACÍA => no filtramos por
    // Id y nos apoyamos en el filtro conductual (el evento debe traer el
    // Requester ID). Rellenar para un filtrado estricto por Id.
    const std::vector<USHORT> kDmaFaultEventIds = { /* p.ej. 0x1234, ... */ };

    bool haveIdFilter()            { return !kDmaFaultEventIds.empty(); }
    bool isFaultId(USHORT id) {
        for (USHORT x : kDmaFaultEventIds) if (x == id) return true;
        return false;
    }

    // Candidatos de nombre de propiedad para cada dato dorado. Distintas builds
    // / providers nombran estos campos de forma distinta; en vez de fijar uno
    // (y perseguir fantasmas), introspeccionamos el esquema y casamos por
    // nombre, sin distinguir mayúsculas.
    const std::initializer_list<const wchar_t*> kReqNames =
        { L"SourceId", L"RequesterId", L"RequesterID", L"DeviceId", L"Bdf", L"BDF" };
    const std::initializer_list<const wchar_t*> kAddrNames =
        { L"Address", L"FaultAddress", L"Iova", L"IOVA", L"VirtualAddress", L"DeviceAddress" };
    const std::initializer_list<const wchar_t*> kRwNames =
        { L"AccessType", L"Access", L"IoType", L"ReadWrite" };

    // Lee el esquema del evento (TRACE_EVENT_INFO) vía TDH. Devuelve el buffer
    // crudo; vacío si el evento no tiene esquema resoluble (frecuente en
    // eventos WPP o sin manifiesto).
    std::vector<BYTE> getEventInfo(PEVENT_RECORD rec) {
        ULONG size = 0;
        TDHSTATUS st = TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
        if (st != ERROR_INSUFFICIENT_BUFFER || size == 0) return {};
        std::vector<BYTE> buf(size);
        st = TdhGetEventInformation(rec, 0, nullptr,
                 reinterpret_cast<PTRACE_EVENT_INFO>(buf.data()), &size);
        if (st != ERROR_SUCCESS) return {};
        return buf;
    }

    // Lee una propiedad escalar (<=8 bytes) por nombre, vía TDH, a un u64.
    bool readScalarU64(PEVENT_RECORD rec, const wchar_t* name, uint64_t& out) {
        PROPERTY_DATA_DESCRIPTOR pd{};
        pd.PropertyName = reinterpret_cast<ULONGLONG>(name);
        pd.ArrayIndex   = ULONG_MAX;
        ULONG sz = 0;
        if (TdhGetPropertySize(rec, 0, nullptr, 1, &pd, &sz) != ERROR_SUCCESS)
            return false;
        if (sz == 0 || sz > sizeof(uint64_t)) return false;
        uint64_t v = 0;
        if (TdhGetProperty(rec, 0, nullptr, 1, &pd, sz,
                           reinterpret_cast<PBYTE>(&v)) != ERROR_SUCCESS)
            return false;
        out = v;
        return true;
    }

    const wchar_t* propName(const BYTE* base, const EVENT_PROPERTY_INFO& pi) {
        return reinterpret_cast<const wchar_t*>(base + pi.NameOffset);
    }

    // Busca el primer campo cuyo nombre casa con algún candidato y lo lee.
    // Con esquema: recorre las propiedades de nivel superior del evento.
    // Sin esquema: prueba los nombres candidatos directamente (por si el
    // provider los resuelve aunque no exponga TRACE_EVENT_INFO completo).
    bool extract(PEVENT_RECORD rec, const std::vector<BYTE>& info,
                 const std::initializer_list<const wchar_t*>& cands, uint64_t& out) {
        if (info.empty()) {
            for (const wchar_t* c : cands)
                if (readScalarU64(rec, c, out)) return true;
            return false;
        }
        auto* tei = reinterpret_cast<const TRACE_EVENT_INFO*>(info.data());
        for (ULONG i = 0; i < tei->TopLevelPropertyCount; ++i) {
            const wchar_t* nm = propName(info.data(), tei->EventPropertyInfoArray[i]);
            for (const wchar_t* c : cands) {
                if (_wcsicmp(nm, c) == 0 && readScalarU64(rec, nm, out))
                    return true;
            }
        }
        return false;
    }
}

EtwConsumer::~EtwConsumer() { stop(); }

void WINAPI EtwConsumer::onEventThunk(PEVENT_RECORD rec) {
    auto* self = static_cast<EtwConsumer*>(rec->UserContext);
    if (self) self->onEvent(rec);
}

void EtwConsumer::onEvent(void* recRaw) {
    auto* rec = static_cast<PEVENT_RECORD>(recRaw);

    // (1) ¿El evento es un fallo de traducción DMA?
    //     - Si hay lista de Ids configurada, exige coincidencia estricta.
    //     - Si no, se acepta de momento y se decide por el payload: un evento
    //       sin Requester ID no es un fallo DMA que nos interese (filtro
    //       conductual que evita tragar todo el provider).
    const USHORT id = rec->EventHeader.EventDescriptor.Id;
    if (haveIdFilter() && !isFaultId(id)) return;

    const std::vector<BYTE> info = getEventInfo(rec);

    // (2) Los dos datos dorados del invariante de comportamiento.
    uint64_t sid = 0, iova = 0, rw = 0;
    const bool haveReq  = extract(rec, info, kReqNames,  sid);
    if (!haveReq) return;                       // sin BDF no hay fallo DMA útil
    const bool haveAddr = extract(rec, info, kAddrNames, iova);
    extract(rec, info, kRwNames, rw);           // acceso R/W: opcional

    // Normaliza el Requester ID de 16 bits a BDF (bus:dev.func).
    const FaultEvent ev = FaultEvent::fromSid(
        static_cast<uint16_t>(sid & 0xFFFF), iova,
        static_cast<uint8_t>(rw & 0x1),
        rec->EventHeader.TimeStamp.QuadPart);

    // Printea el tuple dorado: BDF infractor + IOVA que disparó el bloqueo.
    wprintf(L"[DMA-FAULT] evt=%u  BDF %02x:%02x.%u  IOVA 0x%016llx  %s%s\n",
            static_cast<unsigned>(id),
            static_cast<unsigned>(ev.bus),
            static_cast<unsigned>(ev.dev),
            static_cast<unsigned>(ev.func),
            static_cast<unsigned long long>(ev.iova),
            ev.access ? L"W" : L"R",
            haveAddr ? L"" : L"  (IOVA ausente en el payload)");

    // (3) Entrega al pipeline de correlación (devnode, fingerprint, patrón).
    sink_(ev);
}

bool EtwConsumer::start() {
    const size_t bufLen = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    auto* props = static_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, bufLen));
    if (!props) return false;
    props->Wnode.BufferSize    = static_cast<ULONG>(bufLen);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;                       // QPC
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES));

    TRACEHANDLE h = 0;
    ULONG st = StartTraceW(&h, kSessionName, props);
    if (st == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        st = StartTraceW(&h, kSessionName, props);
    }
    if (st != ERROR_SUCCESS) { free(props); return false; }
    hSession_ = h;

    ENABLE_TRACE_PARAMETERS ep{}; ep.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    EnableTraceEx2(h, &kProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, 0, 0, 0, &ep);

    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = const_cast<LPWSTR>(kSessionName);
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = &EtwConsumer::onEventThunk;
    lf.Context             = this;                        // -> UserContext
    hConsumer_ = OpenTraceW(&lf);
    free(props);
    return hConsumer_ != reinterpret_cast<unsigned long long>(INVALID_HANDLE_VALUE);
}

void EtwConsumer::run() {
    TRACEHANDLE h = hConsumer_;
    ProcessTrace(&h, 1, nullptr, nullptr);                // bloquea
}

void EtwConsumer::stop() {
    if (hConsumer_) { CloseTrace(hConsumer_); hConsumer_ = 0; }
    if (hSession_) {
        const size_t bufLen = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
        auto* props = static_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, bufLen));
        if (props) {
            props->Wnode.BufferSize = static_cast<ULONG>(bufLen);
            props->LoggerNameOffset = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES));
            ControlTraceW(hSession_, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        hSession_ = 0;
    }
}
