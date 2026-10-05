// Tests unitarios del stack_spoof_detector con frames sintéticos (sin SO vivo).
// Un FakeEnv provee los hechos de cada dirección; validamos que la pila limpia
// no dispara nada y que cada anomalía dispara su comprobación correspondiente.
#include "stack_spoof_detector.h"

#include <cstdio>
#include <map>
#include <set>

using namespace sspoof;

namespace {

class FakeEnv : public IStackEnv {
public:
    std::map<uint64_t, FrameFacts> facts;
    std::set<uint64_t>             failCallPreceded;  // direcciones que NO son call-preceded

    FrameFacts classify(uint64_t a) const override {
        const auto it = facts.find(a);
        return (it == facts.end()) ? FrameFacts{} : it->second;
    }
    bool isCallPreceded(uint64_t a) const override {
        return failCallPreceded.find(a) == failCallPreceded.end();
    }
};

// Frame "sano": en módulo, respaldado por imagen, ejecutable, con unwind info.
FrameFacts good(bool thunk = false) {
    FrameFacts f;
    f.inModule = true; f.imageBacked = true; f.executable = true;
    f.hasUnwindInfo = true; f.isThreadStartThunk = thunk;
    return f;
}

int g_fail = 0;
void expect(bool cond, const wchar_t* name) {
    if (cond) { wprintf(L"[ok]   %ls\n", name); }
    else      { wprintf(L"[FAIL] %ls\n", name); ++g_fail; }
}

bool has(const StackVerdict& v, Check c) {
    for (const Finding& f : v.findings) if (f.check == c) return true;
    return false;
}

ThreadStack mkStack(uint64_t a, uint64_t b, uint64_t c, uint64_t rsp) {
    ThreadStack s;
    s.frames = { a, b, c };
    s.stackLimit = 0x9000; s.stackBase = 0x10000; s.rsp = rsp;
    return s;
}

} // namespace

int main() {
    const uint64_t A = 0x1000, B = 0x2000, C = 0x3000;
    const uint64_t RSP_OK = 0xA000;

    // Pila limpia: 3 frames respaldados, outermost = thread-start thunk.
    {
        FakeEnv e;
        e.facts[A] = good(); e.facts[B] = good(); e.facts[C] = good(true);
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, RSP_OK));
        expect(!v.spoofed && v.findings.empty(), L"pila limpia -> sin findings");
    }
    // (1) Un frame no respaldado por imagen (p.ej. RWX privada).
    {
        FakeEnv e; e.facts[A] = good(); e.facts[C] = good(true);
        FrameFacts bad = good(); bad.imageBacked = false; e.facts[B] = bad;
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, RSP_OK));
        expect(v.spoofed && has(v, Check::ReturnInModule), L"no respaldado -> ReturnInModule");
    }
    // (2) Frame en módulo pero sin unwind info.
    {
        FakeEnv e; e.facts[A] = good(); e.facts[C] = good(true);
        FrameFacts bad = good(); bad.hasUnwindInfo = false; e.facts[B] = bad;
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, RSP_OK));
        expect(has(v, Check::UnwindCoherent), L"sin unwind -> UnwindCoherent");
    }
    // (3) RSP fuera de los límites del TEB.
    {
        FakeEnv e; e.facts[A] = good(); e.facts[B] = good(); e.facts[C] = good(true);
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, 0x20000));
        expect(has(v, Check::TebBounds), L"RSP fuera -> TebBounds");
    }
    // (4) Frame no call-preceded.
    {
        FakeEnv e; e.facts[A] = good(); e.facts[B] = good(); e.facts[C] = good(true);
        e.failCallPreceded.insert(B);
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, RSP_OK));
        expect(has(v, Check::CallPreceded), L"no call-preceded -> CallPreceded");
    }
    // (5) El frame exterior no es el thunk de arranque del hilo.
    {
        FakeEnv e; e.facts[A] = good(); e.facts[B] = good(); e.facts[C] = good(false);
        const StackVerdict v = Detector(e).analyze(mkStack(A, B, C, RSP_OK));
        expect(has(v, Check::Termination), L"terminacion mala -> Termination");
    }

    wprintf(L"\n%ls (%d fallos)\n", (g_fail == 0) ? L"TODOS OK" : L"HAY FALLOS", g_fail);
    return (g_fail == 0) ? 0 : 1;
}
