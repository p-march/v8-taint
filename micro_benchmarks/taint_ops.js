var config_benchs = [ 
  [ "Taint-Primitive",
    function(a) { return %_Taint(333); },
    []
  ],
  [ "New-JSObject",
    function(a) { return new Object; },
    []
  ],
  [ "Taint-JSObject",
    function(a) { return %_Taint(new Object); },
    [],
  ],
];

benchs = benchs.concat(init_benchs(config_benchs))
