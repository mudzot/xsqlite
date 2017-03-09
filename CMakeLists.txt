cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 11)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/crypto)

add_library(sqlite3 SHARED
    sqlite3crypt.c
    crypto/sha512.c
    crypto/aes.c
    crypto/aesni.c
)
target_compile_definitions(sqlite3 PRIVATE SQLITE_HAS_CODEC)

add_executable(sqlitenc_cli
    example/sqlitenc_cli.cpp
)
target_compile_definitions(sqlitenc_cli PRIVATE SQLITE_HAS_CODEC)

target_link_libraries(sqlitenc_cli sqlite3 pthread dl)

