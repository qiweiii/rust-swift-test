#!/usr/bin/env bash


# Setup bandersnatch vrf c binding
mkdir -p include
mkdir -p lib

cargo build --lib

cp target/debug/libbandersnatch_vrfs.a lib

cat <<EOL > include/module.modulemap
module bandersnatch_vrfs {
  header "../include/bindings.h"
  link "bandersnatch_vrfs"
  export *
}
EOL

echo "Setup blst successfully."
