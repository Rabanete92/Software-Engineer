#pragma once
#include "types.h"
#include <functional>

// Consumidor ETW en tiempo real. Abre una sesión, habilita el/los providers
// de PnP/DMA-guard, parsea cada evento con TDH y entrega un FaultEvent
// normalizado al sink (la correlación).
class EtwConsumer {
public:
    using Sink = std::function<void(const FaultEvent&)>;

    explicit EtwConsumer(Sink sink) : sink_(std::move(sink)) {}
    ~EtwConsumer();

    bool start();   // StartTrace + EnableTraceEx2 + OpenTrace
    void run();     // ProcessTrace (bloquea hasta stop())
    void stop();

private:
    static void WINAPI onEventThunk(void* rec);   // trampolín a onEvent
    void onEvent(void* rec);

    Sink            sink_;
    unsigned long long hSession_  = 0;
    unsigned long long hConsumer_ = 0;
};
