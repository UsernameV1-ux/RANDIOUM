cmake_minimum_required(VERSION 3.20)
project(Moonrand LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MOONRAND_ENABLE_SLOW_TESTS "Build and register slow tests" OFF)
option(MOONRAND_ENABLE_FUZZ "Build and register fuzz harness" OFF)
option(MOONRAND_ENABLE_BENCH "Build and register benchmark suite" OFF)
option(MOONRAND_ENABLE_PERF_COUNTERS "Enable perf counters" OFF)
option(MOONRAND_ENABLE_EVM "Enable deterministic EVM interpreter (Module 107)" OFF)
option(MOONRAND_ENABLE_MODULE108 "Enable Module 108 (TBD)" OFF)

if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    get_filename_component(MOONRAND_MINGW_BIN "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(MOONRAND_RAW_PATH "$ENV{PATH}")
    string(REPLACE ";" "\\;" MOONRAND_ESC_PATH "${MOONRAND_RAW_PATH}")
    file(TO_NATIVE_PATH "${MOONRAND_MINGW_BIN}" MOONRAND_MINGW_BIN_NATIVE)
    set(MOONRAND_CTEST_PATH "PATH=${MOONRAND_MINGW_BIN_NATIVE}\\;${MOONRAND_ESC_PATH}")

    set(MOONRAND_BUILD_PATH "${MOONRAND_MINGW_BIN_NATIVE};${MOONRAND_RAW_PATH}")
    string(REPLACE ";" "\\;" MOONRAND_BUILD_PATH_ESC "${MOONRAND_BUILD_PATH}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CMAKE_COMMAND}" "-E" "env" "PATH=${MOONRAND_BUILD_PATH_ESC}")
    set(CMAKE_CXX_LINKER_LAUNCHER "${CMAKE_COMMAND}" "-E" "env" "PATH=${MOONRAND_BUILD_PATH_ESC}")
endif ()

add_library(randcore
        src/sha256.cpp
        src/crc32.cpp
        src/hex.cpp
        src/abi_codec.cpp
        src/abi_ts_bindings.cpp
        src/evm_logs.cpp
        src/bridge_message.cpp
        src/bridge_light_verify.cpp
        src/wrap_asset.cpp
        src/wrap_registry.cpp
        src/wrap_contract.cpp
        src/wrap_apply.cpp
        src/oracle.cpp
        src/module118_contract.cpp
        src/module118_apply.cpp
        src/module118_fuzz.cpp
        src/module119_amm_contract.cpp
        src/module119_lend_contract.cpp
        src/module119_amm_apply.cpp
        src/module119_lend_apply.cpp
        src/bridge_spec.cpp
        src/bridge_trusted.cpp
        src/eth_erc20_adapter.cpp
        src/eth_erc721_adapter.cpp
        src/eth_jsonrpc_shim.cpp
        src/tx_codec.cpp
        src/block_codec.cpp
        src/block_full_codec.cpp
        src/varint.cpp
        src/byte_cursor.cpp
        src/hash256_codec.cpp
        src/u64_codec.cpp
        src/rpc_bench.cpp
        src/tps_bench.cpp
        src/proof.cpp
        src/multiproof.cpp
        src/historical_proof.cpp
        src/light_sync.cpp
        src/light_client.cpp
        src/cli.cpp
        src/config.cpp
        src/obs.cpp
        src/audit_trace.cpp
        src/audit_trace_from_exec.cpp
        src/tx.cpp
        src/block.cpp
        src/validate.cpp
        src/storage.cpp
        src/chain_db.cpp
        src/mempool.cpp
        src/p2p_frame.cpp
        src/state.cpp
        src/validator.cpp
        src/staking.cpp
        src/consensus.cpp
        src/checkpoint.cpp
        src/econ_sim.cpp
        src/net_peer.cpp
        src/net_rate.cpp
        src/net_handshake.cpp
        src/net_gossip.cpp
        src/net_sim.cpp
        src/exec_engine.cpp
        src/exec_cache.cpp
        src/vm.cpp
)

if (MOONRAND_ENABLE_EVM)
    target_sources(randcore PRIVATE src/evm.cpp)
endif ()

if (MOONRAND_ENABLE_MODULE108)
    target_sources(randcore PRIVATE src/module108.cpp)
endif ()

target_include_directories(randcore PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(randcore PRIVATE
        $<$<BOOL:${MOONRAND_ENABLE_PERF_COUNTERS}>:MOONRAND_ENABLE_PERF_COUNTERS=1>
)

target_compile_definitions(randcore PUBLIC
        $<$<BOOL:${MOONRAND_ENABLE_EVM}>:MOONRAND_ENABLE_EVM=1>
        $<$<NOT:$<BOOL:${MOONRAND_ENABLE_EVM}>>:MOONRAND_ENABLE_EVM=0>

        $<$<BOOL:${MOONRAND_ENABLE_MODULE108}>:MOONRAND_ENABLE_MODULE108=1>
        $<$<NOT:$<BOOL:${MOONRAND_ENABLE_MODULE108}>>:MOONRAND_ENABLE_MODULE108=0>
)

if (MOONRAND_ENABLE_BENCH OR MOONRAND_ENABLE_PERF_COUNTERS)
    if (MSVC)
        target_compile_options(randcore PRIVATE /UNDEBUG)
    else ()
        target_compile_options(randcore PRIVATE -UNDEBUG)
    endif ()
endif ()

add_executable(Moonrand main.cpp)
target_link_libraries(Moonrand PRIVATE randcore)
