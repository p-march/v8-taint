#!/bin/bash

echo "vanilla"
../d8 --allow_natives_syntax run.js >> x64_v.out
echo "taint level 0"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=0 >> x64_0.out
echo "taint level 1"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=1 >> x64_1.out
echo "taint level 10"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=10 >> x64_10.out
echo "taint level 30"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=30 >> x64_30.out
echo "taint level 50"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=50 >> x64_50.out
echo "taint level 80"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=80 >> x64_80.out
echo "taint level 100"
../d8 --allow_natives_syntax --taint_policy run.js -- taint_level=100 >> x64_100.out
