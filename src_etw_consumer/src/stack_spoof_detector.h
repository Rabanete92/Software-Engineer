#pragma once
// stack_spoof_detector — validación DEFENSIVA de pilas de llamadas para
// desenmascarar spoofing de call stack. Lógica PURA: no toca el SO; recibe los
// hechos de cada dirección de retorno a través de IStackEnv (en producción lo
// implementa un entorno Win32; en tests, un entorno sintético). Aplica las 5
// comprobaciones del invariante:
//   1) ReturnInModule  — retorno respaldado por imagen en disco y ejecutable
//   2) UnwindCoherent  — retorno con RUNTIME_FUNCTION (.pdata) correspondiente
//   3) TebBounds       — RSP dentro de [StackLimit, StackBase) del TEB
//   4) CallPreceded    — el byte previo al retorno es una instrucción call
//   5) Termination     — la cadena termina en el thunk de arranque del hilo
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sspoof {

// Hechos sobre una dirección de retorno, resueltos por el entorno.
struct FrameFacts {
    bool inModule           = false; // cae dentro de un módulo cargado
    bool imageBacked        = false; // respaldado por imagen en disco (MEM_IMAGE)
    bool executable         = false; // región ejecutable
    bool hasUnwindInfo      = false; // RUNTIME_FUNCTION presente (.pdata)
    bool isThreadStartThunk = false; // RtlUserThreadStart / BaseThreadInitThunk
};

// IStackEnv — frontera con el SO (inyección de dependencias).
// POR QUE existe: resolver estos hechos en vivo requiere APIs de Windows
// (VirtualQuery, RtlLookupFunctionEntry, lectura de memoria). Si el detector las
// llamara directamente, su lógica solo podría probarse en una máquina Windows y
// con un proceso real sospechoso a mano. Al abstraer el "entorno" detrás de esta
// interfaz, los tests inyectan un entorno sintético (frames a mano) y validan las
// 5 comprobaciones de forma determinista, sin SO vivo. El motor queda limpio.
class IStackEnv {
public:
    virtual ~IStackEnv() = default;
    virtual FrameFacts classify(uint64_t returnAddr) const = 0;
    virtual bool       isCallPreceded(uint64_t returnAddr) const = 0;
};

struct ThreadStack {
    std::vector<uint64_t> frames;   // return addresses, de interior (0) a exterior
    uint64_t stackBase  = 0;        // TEB StackBase  (límite alto, exclusivo)
    uint64_t stackLimit = 0;        // TEB StackLimit (límite bajo, inclusivo)
    uint64_t rsp        = 0;        // RSP actual (0 = no evaluar bounds)
};

enum class Check { ReturnInModule, UnwindCoherent, TebBounds, CallPreceded, Termination };
enum class Severity { Info = 0, Low = 1, Medium = 2, High = 3 };

const wchar_t* checkName(Check c);
const wchar_t* severityName(Severity s);

struct Finding {
    Check        check;
    size_t       frameIndex;   // SIZE_MAX si aplica a toda la pila
    std::wstring detail;
};

struct StackVerdict {
    bool                 spoofed  = false;
    Severity             severity = Severity::Info;
    std::vector<Finding> findings;
};

class Detector {
public:
    explicit Detector(const IStackEnv& env) : env_(env) {}
    StackVerdict analyze(const ThreadStack& s) const;

private:
    const IStackEnv& env_;
};

} // namespace sspoof
