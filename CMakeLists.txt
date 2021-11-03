cmake_minimum_required(VERSION 3.19)
project(sguclient C)

set(CMAKE_C_STANDARD 11)

include_directories(sguclient-OpenWrt-LuCI/sguclient/src)

add_executable(sguclient
        sguclient-OpenWrt-LuCI/sguclient/src/dprotocol.c
        sguclient-OpenWrt-LuCI/sguclient/src/dprotocol.h
        sguclient-OpenWrt-LuCI/sguclient/src/main.c
        sguclient-OpenWrt-LuCI/sguclient/src/md5.c
        sguclient-OpenWrt-LuCI/sguclient/src/md5.h
        sguclient-OpenWrt-LuCI/sguclient/src/public.c
        sguclient-OpenWrt-LuCI/sguclient/src/public.h
        sguclient-OpenWrt-LuCI/sguclient/src/sguclient.c
        sguclient-OpenWrt-LuCI/sguclient/src/sguclient.h)
