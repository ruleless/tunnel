#!/bin/bash

find \( -name "*.cpp" -o -name "*.[hc]" \) -exec del_trailing_space {} \;

line_count=`find \( -name "*.cpp" -o -name "*.[hc]" \) -exec cat {} \; | awk 'BEGIN{c} {if (length>0) c+=1;} END{print c}'`
echo "total line count of source file: $line_count"
