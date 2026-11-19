# 上游接入：cryptopp（GNUmakefile）→ <build>/pkg/prefix，探针链接 libcryptopp.a。

set(PKG_ROOT "${CMAKE_BINARY_DIR}/pkg")
if(NOT DEFINED PKG_PREFIX)
  set(PKG_PREFIX "${PKG_ROOT}/prefix")
  add_custom_target(pkg ALL
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pkg-build.sh" "${SRC_DIR}" "${PKG_ROOT}" "${RVV_MARCH}" "$<IF:$<BOOL:${RVV_KERNELS}>,1,0>"
    COMMENT "构建上游 cryptopp（${SRC_DIR}）"
    VERBATIM)
  set(HAVE_PKG_TARGET TRUE)
endif()

add_executable(cryptopp_harness test/pkg_cryptopp.cpp)
if(HAVE_PKG_TARGET)
  add_dependencies(cryptopp_harness pkg)
endif()
target_include_directories(cryptopp_harness PRIVATE "${PKG_PREFIX}/include")
target_link_directories(cryptopp_harness PRIVATE "${PKG_PREFIX}/lib")
target_link_libraries(cryptopp_harness PRIVATE cryptopp)
target_compile_options(cryptopp_harness PRIVATE ${RVV_FLAGS})

add_test(NAME cryptopp_harness COMMAND cryptopp_harness)
