function init_benchs(config_benchs) {
  var benchs = new Array();
  
  for (var i in config_benchs) {
    var o = new Object();

    o.name = config_benchs[i][0];
    o.run  = config_benchs[i][1];
    o.args = config_benchs[i][2];
    for (var j = 0; j < o.args.length; j++) {
      if (typeof(o.args[j]) == "function")
        o.args[j] = o.args[j]();
    }

    benchs.push(o)
  }

  for (var i in benchs) {
    benchs[i].iterations = ITER;
  }

  return benchs;
}


function run_bench(bench) {
  var runs = bench.iterations;
  var min_length = MIN;
  var stops = 0;
  var result = 0;
  var length = 0;
  var run = bench.run;
  var a = bench.args[0];
  var b = bench.args[1];
  var c = bench.args[2];

  while (true) {
    var start = %DateCurrentTime();
    for (var i = 0; i < runs; i++) {
      run(a, b, c);
    }
    var end = %DateCurrentTime();
    length += end - start;
    result += runs;
    stops += 1;
    if (length >= min_length)
      break;
  }

  bench.stops = stops;
  bench.length = length;
  bench.result = result;
}


function run_benchs(benchs) {
  for (var i in benchs) {
    run_bench(benchs[i]);
    print((parseInt(i) + 1) + "/" + benchs.length + " " + benchs[i].name + " done")
  } 
}


function report_benchs(benchs) {
  print("\n");

  for (var i in benchs) {
    var result = (benchs[i].result / benchs[i].length / FIX).toFixed(2);
    print("### " + benchs[i].name + " " +
          benchs[i].result + " iterations in " +
          benchs[i].length / FIX + " s " +
          benchs[i].stops + " stops " +
          result + " ops/\u03bcs");
  }

  print("\n");

  for (var i = 0; i < benchs.length; i++) {
    var n_result = (benchs[i].result / benchs[i].length / FIX).toFixed(2);
    if (benchs[i+1] &&
        benchs[i].name.indexOf(benchs[i+1].name.replace(" (T)", "")) == 0) {
      var t_result = (benchs[i+1].result / benchs[i+1].length / FIX).toFixed(2);
      var slowdown = (n_result / t_result).toFixed(2);
      print(benchs[i].name.replace(" (N)", "") + "\t" +
            n_result + "\t" +
            t_result + "\t" +
            slowdown + "x");
      i++
    } else {
      print(benchs[i].name + "\t" + n_result);
    }
  }
}
