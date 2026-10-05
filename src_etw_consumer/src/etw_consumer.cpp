#include "etw_consumer.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>   // calloc / free

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    const wchar_t* kSessionName = L"EdrDmaWatch";

    // -------------------------------------------------------------------------
    // GUID del/los provider(s). RELLENAR tras resolverlos EN TU BUILD con:
    //     logman query providers | findstr /i "dma pnp device guard"
    // No hay un provider "DMA fault" público y documentado con GUID citable;
    // el ancla sólida es Microsoft-Windows-Kernel-Pnp y los canales de
    // seguridad del kernel. Pega aquí el GUID autoritativo de tu máquina.
    // -------------------------------------------------------------------------
    const GUID kProvider = { /* 0x........, ... Microsoft-Windows-Kernel-Pnp */ };

    // Lee una propiedad escalar del evento por nombre, vía TDH.
    bool getU64(PEVENT_RECORD rec, const wchar_t* prop, uint64_t& out) {
        PROPERTY_DATA_DESCRIPTOR pd{};
        pd.PropertyName = reinterpret_cast<ULONGLONG>(prop);
        pd.ArrayIndex   = ULONG_MAX;
        ULONG size = 0;
        if (TdhGetPropertySize(rec, 0, nullptr, 1, &pd, &size) != ERROR_SUCCESS || size == 0 || size > 8)
            return false;
        uint64_t v = 0;
        if (TdhGetProperty(rec, 0, nullptr, 1, &pd,
                           static_cast<ULONG>(sizeof(v)),
                           reinterpret_cast<PBYTE>(&v)) != ERROR_SUCCESS)
            return false;
        out = v;
        return true;
    }
}

EtwConsumer::~EtwConsumer() { stop(); }

void WINAPI EtwConsumer::onEventThunk(PEVENT_RECORD rec) {
    auto* self = static_cast<EtwConsumer*>(rec->UserContext);
    if (self) self->onEvent(rec);
}

void EtwConsumer::onEvent(void* recRaw) {
    auto* rec = static_cast<PEVENT_RECORD>(recRaw);

    // 1) Filtra por provider y por Event Id del fault / arrival relevante.
    //    (Los Ids concretos se identifican con `tracerpt` sobre un .etl de
    //    muestra; se dejan abiertos en este esqueleto.)

    // 2) Extrae el payload. Los nombres de propiedad ("SourceId"/"Address")
    //    dependen del manifiesto del provider en tu build: confírmalos con TDH
    //    (TdhGetEventInformation -> EVENT_PROPERTY_INFO) o con tracerpt.
    uint64_t sid = 0, iova = 0, rw = 0;
    if (!getU64(rec, L"SourceId", sid)) return;   // Requester ID (BDF)
    getU64(rec, L"Address", iova);                // IOVA (puede faltar)
    getU64(rec, L"AccessType", rw);

    // 3) Normaliza y entrega al pipeline de correlación.
    sink_(FaultEvent::fromSid(static_cast<uint16_t>(sid), iova,
                              static_cast<uint8_t>(rw),
                              rec->EventHeader.TimeStamp.QuadPart));
}

bool EtwConsumer::start() {
    const size_t bufLen = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    auto* props = static_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, bufLen));
    if (!props) return false;
    props->Wnode.BufferSize    = static_cast<ULONG>(bufLen);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;                       // QPC
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

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
    lf.LoggerName         = const_cast<LPWSTR>(kSessionName);
    lf.ProcessTraceMode   = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = &EtwConsumer::onEventThunk;
    lf.Context            = this;                         // -> UserContext
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
            props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(hSession_, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        hSession_ = 0;
    }
}
