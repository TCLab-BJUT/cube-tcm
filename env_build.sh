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
cd vtcm_manager
ln -s $CUBESYSPATH/main/main_proc
cd -
cd vtcm_utils
ln -s $CUBESYSPATH/main/main_proc
cd -

cd locallib
make
cd -

cd module
make 
cd -

cd init_module/vtcm_init
make
cd -

