#include "stack_spoof_detector.h"

namespace sspoof {
namespace {
Severity maxSev(Severity a, Severity b) {
    return (static_cast<int>(a) >= static_cast<int>(b)) ? a : b;
}
} // namespace

const wchar_t* checkName(Check c) {
    const wchar_t* r = L"?";
    switch (c) {
        case Check::ReturnInModule: r = L"ReturnInModule"; break;
        case Check::UnwindCoherent: r = L"UnwindCoherent"; break;
        case Check::TebBounds:      r = L"TebBounds";      break;
        case Check::CallPreceded:   r = L"CallPreceded";   break;
        case Check::Termination:    r = L"Termination";    break;
    }
    return r;
}

const wchar_t* severityName(Severity s) {
    const wchar_t* r = L"INFO";
    switch (s) {
        case Severity::High:   r = L"HIGH";   break;
        case Severity::Medium: r = L"MEDIUM"; break;
        case Severity::Low:    r = L"LOW";    break;
        case Severity::Info:   r = L"INFO";   break;
    }
    return r;
}

StackVerdict Detector::analyze(const ThreadStack& s) const {
    StackVerdict v;
    auto add = [&](Check c, size_t idx, Severity sev, const wchar_t* d) {
        v.findings.push_back(Finding{ c, idx, std::wstring(d) });
        v.severity = maxSev(v.severity, sev);
        v.spoofed  = true;
    };

    // (3) TEB bounds: RSP dentro de [StackLimit, StackBase).
    //     POR QUE: cada hilo tiene una pila real asignada por el SO, cuyos
    //     limites viven en el TEB. Los atacantes suelen FORJAR una pila falsa en
    //     memoria cualquiera (heap, region privada reservada aparte) y apuntar
    //     ahi; si el RSP no cae dentro del rango legitimo del hilo, esa "pila"
    //     es sintetica, no la que el SO le dio.
    if (s.rsp != 0 && s.stackBase != 0) {
        if (s.rsp < s.stackLimit || s.rsp >= s.stackBase)
            add(Check::TebBounds, SIZE_MAX, Severity::High,
                L"RSP fuera de los limites de pila del TEB");
    }

    const size_t n = s.frames.size();
    for (size_t i = 0; i < n; ++i) {
        const uint64_t  a = s.frames[i];
        const FrameFacts f = env_.classify(a);
        const bool outermost = (i + 1 == n);

        // (1) Return address respaldada por imagen en disco y ejecutable.
        //     POR QUE: el codigo inyectado (shellcode, modulos "manual-mapped")
        //     vive en memoria privada/RWX sin un archivo en disco detras. Un
        //     retorno que apunta a esa memoria delata codigo que no proviene de
        //     ningun binario cargado legitimamente = implante en memoria.
        if (!(f.inModule && f.imageBacked && f.executable))
            add(Check::ReturnInModule, i, Severity::High,
                L"return address no respaldada por imagen en disco / no ejecutable");

        // (2) Coherencia de unwind (solo tiene sentido si cae en un modulo Y el
        //     entorno pudo evaluar el unwind; cross-process no puede, y gatearlo
        //     evita marcar como spoof cada frame legitimo de otro proceso).
        //     POR QUE: toda funcion real que un compilador genera queda
        //     registrada en los datos de unwind del modulo (.pdata). Un retorno
        //     dentro de un modulo pero SIN entrada de unwind apunta a un offset
        //     que ninguna funcion legitima ocupa: tipico de gadgets/ROP o de un
        //     frame falso incrustado para imitar a ese modulo.
        if (f.unwindChecked && f.inModule && !f.hasUnwindInfo)
            add(Check::UnwindCoherent, i, Severity::High,
                L"return address sin RUNTIME_FUNCTION (.pdata) correspondiente");

        // (4) Call-preceded (excepto el frame de terminacion, que es un entry).
        //     POR QUE: una direccion de retorno legitima SIEMPRE la dejo en la
        //     pila la instruccion `call` que esta justo antes de ella. Si el byte
        //     previo no es un call, esa direccion no la puso ninguna llamada
        //     real: la escribio el atacante "a mano" para rellenar la pila falsa.
        if (!outermost && !env_.isCallPreceded(a))
            add(Check::CallPreceded, i, Severity::High,
                L"el byte previo al retorno no corresponde a una instruccion call");
    }

    // (5) Terminacion en el thunk de arranque del hilo.
    //     POR QUE: toda pila real nace donde el SO arranco el hilo
    //     (RtlUserThreadStart -> BaseThreadInitThunk). Un atacante que recorta o
    //     fabrica la cadena para ocultar su verdadero origen rara vez reproduce
    //     ese fondo: una pila que no termina ahi esta truncada o inventada.
    if (n > 0) {
        const FrameFacts last = env_.classify(s.frames[n - 1]);
        if (!last.isThreadStartThunk)
            add(Check::Termination, n - 1, Severity::Medium,
                L"la cadena no termina en RtlUserThreadStart/BaseThreadInitThunk");
    }

    return v;
}

} // namespace sspoof
