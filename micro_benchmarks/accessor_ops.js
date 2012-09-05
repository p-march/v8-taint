var config_benchs = [

  [ "Call",
    function() { return a.c(); },
    [],
  ],
  [ "Load",
    function() { return a.b; },
    [],
  ],
  [ "KeyedLoad",
    function(b) { return a[b]; },
    [ "b" ],
  ],
  [ "Store",
    function(c) { return a.b = c; },
    [ 2 ],
  ],
  [ "KeyedStore",
    function(b, c) { return a[b] = c; },
    [ "b",
      2 ],
  ],

];

benchs = benchs.concat(init_benchs(config_benchs))
