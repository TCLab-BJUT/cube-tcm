#!/bin/bash

if [ $CUBESYSPATH == "" ]
then
    echo "can't find CUBESYSPATH"
    exit
fi

echo "CUBESYSPATH is ${CUBESYSPATH}"

cd vtcm_hub
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_emulator
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_new_emulator
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_manager
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_utils
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_v0_utils
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_v1_utils
ln -s $CUBESYSPATH/main/main_proc
cd -

cd locallib
make clean
make
cd -

cd module
make clean
make
cd -

cd init_module/vtcm_init
make clean
make
cd -

