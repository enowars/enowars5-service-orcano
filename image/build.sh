#!/bin/bash
cd $(dirname $0)
docker build -t orcano-image .
docker create -ti --name dummy orcano-image bash
MSYS2_ARG_CONV_EXCL="*" docker cp dummy:/image/image.dol ./image.dol
MSYS2_ARG_CONV_EXCL="*" docker cp dummy:/image/image.elf ./image.elf
MSYS2_ARG_CONV_EXCL="*" docker cp dummy:/image/image.map ./image.map
docker rm -fv dummy