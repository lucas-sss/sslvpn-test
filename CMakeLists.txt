cmake_minimum_required(VERSION 2.8)
project(openssl-example CXX)

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

aux_source_directory(${PROJECT_SOURCE_DIR}/engine engine_source)

# macos暂时不编译服务端
IF (NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
add_executable(sslvpn sslvpn.cc tun.cc protocol.cc cJSON.cc print.cc proxy.cc ${engine_source})
if(SDF)
    target_link_libraries(sslvpn ssl crypto pthread sdf_crypto)
else()
    target_link_libraries(sslvpn ssl crypto pthread)
endif()
ENDIF ()

# IF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
# add_executable(sslvpn-client sslvpn-client.cc tun.cc protocol.cc cJSON.cc print.cc)
# ELSE ()

# ENDIF ()
add_executable(sslvpn-client sslvpn-client.cc tun.cc protocol.cc cJSON.cc print.cc ${engine_source})

if(SDF)
    target_link_libraries(sslvpn-client ssl crypto pthread sdf_crypto)
else()
    target_link_libraries(sslvpn-client ssl crypto pthread)
endif()

# 拷贝文件夹到指定的目录
add_custom_target(copy_certs ALL  
  VERBATIM 
  # COMMAND_EXPAND_LISTS 
  COMMAND ${CMAKE_COMMAND} -E 
                  copy_directory  
                  "${CMAKE_CURRENT_SOURCE_DIR}/certs" 
                  "certs" 
) 

