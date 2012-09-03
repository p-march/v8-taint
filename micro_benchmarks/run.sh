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

OUT=0

for i in ${PARAMS[@]}
do
  let OUT++
  echo $i > $OUT
  echo >> $OUT
  for j in {1..10}
  do
    $V8 $BENCH $DEFAULT_PARAMS $i >> $OUT
  done
  $PARSER $OUT > "${OUT}_out"
done
