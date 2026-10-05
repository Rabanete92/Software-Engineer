#===============================================================================
# DMA-EDR PoC  —  Consumidor ETW + correlación de postura DMA (user-mode service)
#
# DEFENSIVO. Captura {BDF, IOVA} de los eventos de PnP/DMA-guard del kernel y los
# cruza con SetupAPI para resolver el devnode y su postura de DMA remapping.
#
# Sobre PPL: NO hay "manifiesto PPL". Lo único que aporta el BUILD es:
#   (1) /INTEGRITYCHECK  -> el loader exige firma válida del binario.
#   (2) recurso ELAM embebido (elam.rc) con la info del certificado AM.
#   (3) firma post-build con el certificado anti-malware de Microsoft.
# El lanzamiento protegido se hace en runtime (ver src/main.cpp, install).
#===============================================================================
cmake_minimum_required(VERSION 3.21)
project(dma_edr_poc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(edrsvc
    src/main.cpp
    src/etw_consumer.cpp
    src/correlation.cpp
    src/byovd_detector.cpp
    src/image_load_consumer.cpp
    src/stack_spoof_detector.cpp
    # elam.rc            # <- descomenta cuando tengas el recurso ELAM (ver README)
)

target_include_directories(edrsvc PRIVATE src)

# Librerías: ETW consumer (advapi32), parseo de esquema de eventos (tdh),
# enumeración de devnodes y propiedades (setupapi, cfgmgr32).
target_link_libraries(edrsvc PRIVATE advapi32 tdh setupapi cfgmgr32)

if (MSVC)
    # /WX: cero tolerancia a warnings. Un consumidor que opera a nivel EDR no
    # puede arrastrar conversiones implícitas ni formatos mal tipados.
    target_compile_options(edrsvc PRIVATE /W4 /WX /permissive- /guard:cf)

    # (1) Pieza build-time de PPL: fuerza validación de firma en el load.
    #     OJO: con /INTEGRITYCHECK el binario NO carga si no está firmado.
    target_link_options(edrsvc PRIVATE /INTEGRITYCHECK /guard:cf)

    # (3) Firma post-build con el cert AM. Requiere el cert del programa
    #     anti-malware de Microsoft; sin él, esto es un placeholder.
    #     Descomenta y ajusta cuando dispongas del certificado.
    # add_custom_command(TARGET edrsvc POST_BUILD
    #     COMMAND signtool sign /v /fd SHA256
    #             /n "Tu Anti-Malware CN"
    #             /tr http://timestamp.digicert.com /td SHA256
    #             "$<TARGET_FILE:edrsvc>"
    #     COMMENT "Firmando con certificado anti-malware (PPL)")
endif()

#-------------------------------------------------------------------------------
# Tests unitarios (lógica pura; no requieren Windows vivo). El detector de
# call-stack se valida con frames sintéticos vía CTest.
#-------------------------------------------------------------------------------
enable_testing()
add_executable(stack_spoof_tests
    test/stack_spoof_tests.cpp
    src/stack_spoof_detector.cpp
)
target_include_directories(stack_spoof_tests PRIVATE src)
if (MSVC)
    target_compile_options(stack_spoof_tests PRIVATE /W4 /WX /permissive-)
endif()
add_test(NAME stack_spoof COMMAND stack_spoof_tests)
