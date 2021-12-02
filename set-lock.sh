#!/bin/bash

TARGET=$1

case $TARGET in
    icecap|linux|nitro|sgx|tz) echo "Setting Cargo.lock files for ${TARGET}" ;;
    *) echo "Unknown target '${TARGET}'" ; exit 255 ;; 
esac

for i in $(find . -name Cargo.lock.${TARGET}) ; do
    if [ -f $(dirname $i)/Cargo.lock ] ; then
        if ! cmp --quiet $i $(dirname $i)/Cargo.lock ; then
           cp -v $i $(dirname $i)/Cargo.lock
        fi
    else
        cp -v $i $(dirname $i)/Cargo.lock
    fi
done
