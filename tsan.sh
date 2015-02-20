#!/bin/bash
clang -o throughput -fsanitize=thread -fPIE -pie -ggdb3 -I/usr/local/include -L/usr/local/lib -DINET -DINET6 throughput.c -lusrsctp -lpthread
