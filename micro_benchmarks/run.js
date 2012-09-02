var MIN = 5000;
var ITER = 100000000;
var FIX = 1000;


//var MIN = 1000;
//var ITER = 100000;

var benchs = new Array();

load("base.js");
load("unary_ops.js");
load("binary_ops.js");
load("property_ops.js");
load("taint_ops.js");

run_benchs(benchs)
report_benchs(benchs)
