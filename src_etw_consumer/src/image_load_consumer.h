#pragma once
// image_load_consumer — consumidor ETW en vivo de cargas de imagen (módulos/
// drivers). Suscribe el provider de image-load del kernel, extrae la ruta del
// módulo + PID, decide si la carga es en modo kernel (.sys / System), y pasa el
// evento a byovd::Detector. Instrumenta además la sesión con captura de pila
// (EVENT_ENABLE_PROPERTY_STACK_TRACE) como puente al módulo de call-stack.
// DEFENSIVO: solo observa y clasifica; no carga ni ejecuta nada.
#include "byovd_detector.h"
#include <windows.h>
#include <evntcons.h>

class ImageLoadConsumer {
public:
    explicit ImageLoadConsumer(const byovd::Detector* det) : det_(det) {}
    ~ImageLoadConsumer();

    bool start();   // StartTrace + EnableTraceEx2(+stack trace) + OpenTrace
    void run();     // ProcessTrace (bloquea hasta stop())
    void stop();

private:
    static void WINAPI onEventThunk(PEVENT_RECORD rec);
    void onEvent(PEVENT_RECORD rec);

    const byovd::Detector* det_       = nullptr;
    unsigned long long     hSession_  = 0;
    unsigned long long     hConsumer_ = 0;
};
