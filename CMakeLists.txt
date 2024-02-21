cmake_minimum_required(VERSION 2.8)
project(openssl-example CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set(NO_SDF OFF)
option(NO_SDF "soft crypto in engine" ON)

# 是否使用加密卡宏控制
if(NO_SDF)
  add_definitions(-DNO_SDF)
endif()

# add_compile_options(-Wall -Wextra -pedantic -Werror)
add_compile_options(-fpermissive)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -std=c++11")

include_directories(
  ${PROJECT_SOURCE_DIR}/include
  "/opt/tongsuo/include"
  ${PROJECT_SOURCE_DIR}/engine
)

link_directories("/opt/tongsuo/lib64")
# link_directories("/home/cq/new_arch/Tongsuo/lib64_opt")

aux_source_directory(${PROJECT_SOURCE_DIR}/engine engine_source)

add_executable(sslvpn sslvpn.cc tun.cc protocol.cc cJSON.cc print.cc proxy.cc ${engine_source})
if(NO_SDF)
  target_link_libraries(sslvpn ssl crypto pthread)
else()
  target_link_libraries(sslvpn ssl crypto pthread sdf_crypto)
endif()

add_executable(sslvpn-client sslvpn-client.cc tun.cc protocol.cc cJSON.cc print.cc ${engine_source})
if(NO_SDF)
  target_link_libraries(sslvpn-client ssl crypto pthread)
else()
  target_link_libraries(sslvpn-client ssl crypto pthread sdf_crypto)
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

