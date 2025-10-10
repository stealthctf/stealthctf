#!/bin/bash
SIZE=$(du --max-depth=0 /opt | cut -f 1 )
echo $SIZE
# 2GB = 2147483648 bytes
# 10GB = 10737418240 bytes
if [[ $SIZE -gt 2147483648 && $SIZE -lt 10737418240 ]]; then
    echo 'Condition returned True'
fi
