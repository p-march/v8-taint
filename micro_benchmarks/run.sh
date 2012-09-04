#!/bin/bash

V8="../d8"
BENCH="run.js"
DEFAULT_PARAMS="--allow_natives_syntax --taint_policy"
PARAMS=(
  "--noopt --nouse_taint_spec"
  "--noopt"
  "--noopt --notaint_result"
  "--noloop_invariant_code_motion --nouse_taint_spec"
  "--noloop_invariant_code_motion"
  "--noloop_invariant_code_motion --notaint_result"
)
PARSER="./parser.py"

for (( i=0; i<${#PARAMS[@]}; i++ ))
do
  echo ${PARAMS[$i]} > $i
  echo >> $i
  for j in {1..10}
  do
    $V8 $BENCH $DEFAULT_PARAMS ${PARAMS[$i]} >> $i
  done
  echo ${PARAMS[$i]} > "${i}_out"
  $PARSER $i >> "${i}_out"
done
