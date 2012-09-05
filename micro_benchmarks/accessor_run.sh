#!/bin/bash

V8="./accessor_bench"
BENCH="accessor_run.js"
DEFAULT_PARAMS="--allow_natives_syntax"
PARAMS=(
  "--noopt"
  "--noopt --taint_policy"
  "--noloop_invariant_code_motion"
  "--noloop_invariant_code_motion --taint_policy"
)
PARSER="./parser.py"
TAINT_POLICY="taint_policy_null.js"

cp $TAINT_POLICY  taint_policy.js

for (( i=0; i<${#PARAMS[@]}; i++ ))
do
  echo $TAINT_POLICY > "${i}a"
  echo ${PARAMS[$i]} >> "${i}a"
  echo >> "${i}a"
  for j in {1..2}
  do
    $V8 $BENCH $DEFAULT_PARAMS ${PARAMS[$i]} >> "${i}a"
  done
  echo $TAINT_POLICY > "${i}a_out"
  echo ${PARAMS[$i]} >> "${i}a_out"
  $PARSER "${i}a" >> "${i}a_out"
done

TAINT_POLICY="taint_policy_nothing.js"

cp $TAINT_POLICY  taint_policy.js

for (( i=0; i<${#PARAMS[@]}; i++ ))
do
  echo $TAINT_POLICY > "${i}b"
  echo ${PARAMS[$i]} >> "${i}b"
  echo >> "${i}b"
  for j in {1..2}
  do
    $V8 $BENCH $DEFAULT_PARAMS ${PARAMS[$i]} >> "${i}b"
  done
  echo $TAINT_POLICY > "${i}b_out"
  echo ${PARAMS[$i]} >> "${i}b_out"
  $PARSER "${i}b" >> "${i}b_out"
done