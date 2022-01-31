cmake_minimum_required(VERSION 3.19)
project(sguclient C)

set(CMAKE_C_STANDARD 17)

include_directories(sguclient-linux)

add_executable(sguclient
        sguclient-linux/dprotocol.c
        sguclient-linux/dprotocol.h
        sguclient-linux/main.c
        sguclient-linux/md5.c
        sguclient-linux/md5.h
        sguclient-linux/public.c
        sguclient-linux/public.h
        sguclient-linux/sguclient.c
        sguclient-linux/sguclient.h
        sguclient-linux/sha1.c
        sguclient-linux/sha1.h
        sguclient-linux/md4.c
        sguclient-linux/md4.h)
