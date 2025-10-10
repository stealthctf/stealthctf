#!/bin/bash
while true; do docker run --rm --name acsc2 -d -p 80:80 -p 443:443 -p 8443:8443 -p 1881:1881 acsc2; sleep 10; done
