var MIN = 5000;
var ITER = ITER ? ITER : 100000000;
var FIX = 1000;

var MIN = 1000;
var ITER = 3000;

var benchs = new Array();

load("base.js");
load("accessor_ops.js");

run_benchs(benchs)
report_benchs(benchs)
