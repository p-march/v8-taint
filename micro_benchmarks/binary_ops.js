var config_benchs = [ 
  [ "Add-I (N)",   function(a, b) { return a + b; },   [ 333,           222 ] ],
  [ "Add-I (T)",   function(a, b) { return a + b; },   [ %Taint(333),   %Taint(222) ] ],
  [ "Sub-I (N)",   function(a, b) { return a - b; },   [ 333,           222 ] ],
  [ "Sub-I (T)",   function(a, b) { return a - b; },   [ %Taint(333),   %Taint(222) ] ],
  [ "Mul-I (N)",   function(a, b) { return a * b; },   [ 333,           333 ] ],
  [ "Mul-I (T)",   function(a, b) { return a * b; },   [ %Taint(333),   %Taint(333) ] ],
  [ "Div-I (N)",   function(a, b) { return a / b; },   [ 999,           333 ] ],
  [ "Div-I (T)",   function(a, b) { return a / b; },   [ %Taint(999),   %Taint(333) ] ],
  [ "Add-D (N)",   function(a, b) { return a + b; },   [ 1.1,           1.1 ] ],
  [ "Add-D (T)",   function(a, b) { return a + b; },   [ %Taint(1.1),   %Taint(1.1) ] ],
  [ "Sub-D (N)",   function(a, b) { return a - b; },   [ 2.1,           2.2 ] ],
  [ "Sub-D (T)",   function(a, b) { return a - b; },   [ %Taint(2.1),   %Taint(2.2) ] ],
  [ "Div-D (N)",   function(a, b) { return a / b; },   [ 3.5,           1.1 ] ],
  [ "Div-D (T)",   function(a, b) { return a / b; },   [ %Taint(3.5),   %Taint(1.1) ] ],
  [ "Add-S (N)",   function(a, b) { return a + b; },   [ "1",           "2" ] ],
  [ "Add-S (T)",   function(a, b) { return a + b; },   [ %Taint("1"),   %Taint("2") ] ],
];

benchs = benchs.concat(init_benchs(config_benchs));
