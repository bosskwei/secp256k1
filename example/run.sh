#! /bin/bash

cd build

if [[ $1 ]]; then
    rm -rf *
fi

cmake ..
make -j4

if [[ $? != 0 ]]; then
    exit $?
fi

nice -10 ./deqp-vk

