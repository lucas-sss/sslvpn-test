cmake_minimum_required(VERSION 2.8)
project(engine CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set(SDF OFF)
option(SDF "soft crypto in engine" ON)

# 是否使用加密卡宏控制
if(NOT SDF)
  add_definitions(-DNO_SDF)
endif()

# add_compile_options(-Wall -Wextra -pedantic -Werror)
add_compile_options(-fpermissive)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -std=c++11")

IF (CMAKE_SYSTEM_NAME MATCHES "Linux") 
    MESSAGE(STATUS "current platform: Linux ") 
    include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/engine
        "/opt/tongsuo/include"
    )
    link_directories("/opt/tongsuo/lib64")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows") 
    MESSAGE(STATUS "current platform: Windows") 
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Darwin") 
    MESSAGE(STATUS "current platform: Mac OS X")
    include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/engine
        "/Users/liuwei/Applications/tongsuo/include"
    )
    link_directories("/Users/liuwei/Applications/tongsuo/lib")
ENDIF ()


# macos暂时不编译服务端
IF (NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_library(flk_ssl_engine SHARED
        ec_helper.cc
        random.cc
        sdf_handler.cc
        sm2.cc
        sm3.cc
        sm4.cc
        ssl_engine.cc)
if(SDF)
        target_link_libraries(flk_ssl_engine ssl crypto sdf_crypto)
else()
        target_link_libraries(flk_ssl_engine ssl crypto)
endif()
ENDIF ()

set_target_properties(flk_ssl_engine PROPERTIES PREFIX "")


