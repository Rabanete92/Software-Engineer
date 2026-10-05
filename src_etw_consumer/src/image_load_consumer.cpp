#include "image_load_consumer.h"
#include "stack_spoof_detector.h"
#include "win32_stack_env.h"

#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <climits>
#include <initializer_list>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace {
    const wchar_t* kSessionName = L"EdrImgWatch";

    // -------------------------------------------------------------------------
    // Provider de image-load. Default sensato: Microsoft-Windows-Kernel-Process
    // (manifest provider, habilitable desde una sesión real-time normal), con el
    // keyword IMAGE y el Event Id 5 = ImageLoad. CONFIRMAR EN TU BUILD:
    //   logman query providers "Microsoft-Windows-Kernel-Process"
    // Nota: las cargas de driver en kernel se atribuyen al proceso System (PID 4);
    // si necesitas cobertura estricta de drivers, el NT Kernel Logger (flag
    // EVENT_TRACE_FLAG_IMAGE_LOAD) es la otra vía. El nombre de la propiedad de
    // ruta ("ImageName") se confirma con tracerpt/TDH; dejamos candidatos.
    // -------------------------------------------------------------------------
    const GUID  kKernelProcess =
        { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0,0xC7,0x2F,0xAD,0x1F,0xD0,0xE7,0x16 } };
    const ULONGLONG kKeywordImage   = 0x0000000000000040ULL; // WINEVENT_KEYWORD_IMAGE
    const USHORT    kImageLoadEvent = 5;                       // ImageLoad

    bool readPropStr(PEVENT_RECORD rec, const wchar_t* name, std::wstring& out) {
        PROPERTY_DATA_DESCRIPTOR pd{};
        pd.PropertyName = reinterpret_cast<ULONGLONG>(name);
        pd.ArrayIndex   = ULONG_MAX;
        ULONG sz = 0;
        if (TdhGetPropertySize(rec, 0, nullptr, 1, &pd, &sz) != ERROR_SUCCESS || sz == 0)
            return false;
        std::wstring buf;
        buf.resize(sz / sizeof(wchar_t) + 1);
        if (TdhGetProperty(rec, 0, nullptr, 1, &pd, sz,
                           reinterpret_cast<PBYTE>(buf.data())) != ERROR_SUCCESS)
            return false;
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        if (buf.empty()) return false;
        out = buf;
        return true;
    }

    bool readPropU64(PEVENT_RECORD rec, const wchar_t* name, uint64_t& out) {
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

    bool extractStr(PEVENT_RECORD rec,
                    std::initializer_list<const wchar_t*> cands, std::wstring& out) {
        for (const wchar_t* c : cands) if (readPropStr(rec, c, out)) return true;
        return false;
    }

    bool endsWithSysCI(const std::wstring& p) {
        if (p.size() < 4) return false;
        std::wstring e = p.substr(p.size() - 4);
        for (wchar_t& c : e) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        return e == L".sys";
    }

    // Cuenta los frames de pila adjuntos al evento (si la sesión los capturó).
    USHORT countStackFrames(PEVENT_RECORD rec) {
        for (USHORT i = 0; i < rec->ExtendedDataCount; ++i) {
            const USHORT t = rec->ExtendedData[i].ExtType;
            const ULONG  n = rec->ExtendedData[i].DataSize;
            if (t == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 && n > sizeof(ULONG64))
                return static_cast<USHORT>((n - sizeof(ULONG64)) / sizeof(ULONG64));
            if (t == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 && n > sizeof(ULONG))
                return static_cast<USHORT>((n - sizeof(ULONG)) / sizeof(ULONG));
        }
        return 0;
    }

    // Extrae las direcciones de retorno USER-MODE de la pila adjunta (x64). Se
    // descartan las direcciones de kernel (rango canonico alto): el validador de
    // spoofing razona sobre modulos de usuario y los frames de kernel darian
    // falsos "no respaldado". Orden: interior -> exterior, como espera el Detector.
    std::vector<uint64_t> extractUserFrames(PEVENT_RECORD rec) {
        std::vector<uint64_t> out;
        for (USHORT i = 0; i < rec->ExtendedDataCount; ++i) {
            const auto& ext = rec->ExtendedData[i];
            if (ext.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) continue;
            if (ext.DataSize <= sizeof(ULONG64)) continue;
            const auto* st = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE64*>(
                static_cast<uintptr_t>(ext.DataPtr));
            const size_t count = (ext.DataSize - sizeof(ULONG64)) / sizeof(ULONG64);
            for (size_t k = 0; k < count; ++k) {
                const uint64_t a = static_cast<uint64_t>(st->Address[k]);
                if (a != 0 && a < 0x0000800000000000ULL)   // solo user-mode (x64)
                    out.push_back(a);
            }
        }
        return out;
    }

    // Enriquecimiento: valida la postura de la pila capturada contra el proceso
    // originante. TebBounds queda sin evaluar (el evento no trae el TEB del hilo);
    // el unwind se auto-desactiva cross-process (ver Win32StackEnv). Correctas
    // cross-process: ReturnInModule, CallPreceded y Termination.
    void analyzeStack(ULONG pid, const std::vector<uint64_t>& frames) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) {
            wprintf(L"   [stack] no se pudo abrir pid=%lu para analizar la pila (err=%lu)\n",
                    static_cast<unsigned long>(pid),
                    static_cast<unsigned long>(GetLastError()));
            return;
        }
        sspoof::Win32StackEnv env(hProc);
        sspoof::ThreadStack s;
        s.frames = frames;   // base/limit/rsp = 0 -> TebBounds no evaluado
        const sspoof::StackVerdict v = sspoof::Detector(env).analyze(s);
        wprintf(L"   [stack] frames_user=%zu  spoofed=%ls  sev=%ls\n",
                frames.size(), v.spoofed ? L"si" : L"no",
                sspoof::severityName(v.severity));
        for (const sspoof::Finding& f : v.findings) {
            if (f.frameIndex == SIZE_MAX)
                wprintf(L"      - [%ls] (pila): %ls\n",
                        sspoof::checkName(f.check), f.detail.c_str());
            else
                wprintf(L"      - [%ls] frame#%zu: %ls\n",
                        sspoof::checkName(f.check), f.frameIndex, f.detail.c_str());
        }
        CloseHandle(hProc);
    }
}

ImageLoadConsumer::~ImageLoadConsumer() { stop(); }

void WINAPI ImageLoadConsumer::onEventThunk(PEVENT_RECORD rec) {
    auto* self = static_cast<ImageLoadConsumer*>(rec->UserContext);
    if (self) self->onEvent(rec);
}

void ImageLoadConsumer::onEvent(PEVENT_RECORD rec) {
    if (!det_) return;
    if (rec->EventHeader.EventDescriptor.Id != kImageLoadEvent) return;

    std::wstring path;
    if (!extractStr(rec, { L"ImageName", L"FileName", L"ImageFileName" }, path))
        return;   // sin ruta no hay nada que evaluar

    byovd::ImageLoad img;
    img.path = path;
    readPropU64(rec, L"ImageBase", img.imageBase);
    const ULONG pid = rec->EventHeader.ProcessId;
    img.kernelMode = endsWithSysCI(path) || (pid == 4);   // System = cargas de driver

    const byovd::Verdict v = det_->evaluate(img);
    if (!v.alert()) return;   // silencioso salvo alerta (evita inundar)

    const USHORT frames = countStackFrames(rec);
    wprintf(L"[IMAGE-ALERT] %s  pid=%lu%s  sev=%s  (stack: %u frames)\n",
            path.c_str(), static_cast<unsigned long>(pid),
            img.kernelMode ? L" kernel" : L"",
            byovd::severityName(v.severity), static_cast<unsigned>(frames));
    for (const std::wstring& r : v.reasons) wprintf(L"   - %s\n", r.c_str());

    // Enriquecer la alerta con la postura de la pila capturada por ETW.
    const std::vector<uint64_t> uframes = extractUserFrames(rec);
    if (!uframes.empty()) analyzeStack(pid, uframes);
}

bool ImageLoadConsumer::start() {
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

    // Puente al módulo de call-stack: pedir que el kernel adjunte la pila a cada
    // evento del provider (EVENT_ENABLE_PROPERTY_STACK_TRACE).
    ENABLE_TRACE_PARAMETERS ep{};
    ep.Version        = ENABLE_TRACE_PARAMETERS_VERSION_2;
    ep.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
    EnableTraceEx2(h, &kKernelProcess, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, kKeywordImage, 0, 0, &ep);

    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = const_cast<LPWSTR>(kSessionName);
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = &ImageLoadConsumer::onEventThunk;
    lf.Context             = this;                        // -> UserContext
    hConsumer_ = OpenTraceW(&lf);
    free(props);
    return hConsumer_ != reinterpret_cast<unsigned long long>(INVALID_HANDLE_VALUE);
}

void ImageLoadConsumer::run() {
    TRACEHANDLE h = hConsumer_;
    ProcessTrace(&h, 1, nullptr, nullptr);
}

void ImageLoadConsumer::stop() {
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
