#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID= 5a4461d8a3948d9d26bf861e7d90cb80d8093515

cd ..
# git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
git clone https://github.com/h2o/picotls
cd picotls
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
echo "Using options:  $PTLS_CMAKE_OPTS"
cmake $PTLS_CMAKE_OPTS .
make -j$(nproc) all
cd ..
