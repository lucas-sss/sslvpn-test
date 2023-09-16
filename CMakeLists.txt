cmake_minimum_required(VERSION 2.8)
project(openssl-example CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)


#add_compile_options(-Wall -Wextra -pedantic -Werror)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -std=c++11")

include_directories("/opt/tongsuo/include")
link_directories("/opt/tongsuo/lib64")


add_executable(sslvpn-test sslvpn_test.cc tun.cc protocol.cc)
target_link_libraries(sslvpn-test ssl crypto pthread)

# 拷贝文件夹到指定的目录
add_custom_target(copy_certs ALL  
  VERBATIM 
  # COMMAND_EXPAND_LISTS 
  COMMAND ${CMAKE_COMMAND} -E 
                  copy_directory  
                  "${CMAKE_CURRENT_SOURCE_DIR}/certs" 
                  "certs" 
) 

