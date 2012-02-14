// Copyright 2009 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Flags: --allow_natives_syntax --taint_policy


function assertTaintEquals(res, op1, op2, comment) {
  assertFalse(%_IsTainted(op1));
  assertFalse(%_IsTainted(op2));
  assertTrue(%_IsTainted(%Taint(op1) + op2));
  %Untaint(op1);
  assertTrue(%_IsTainted(op1 + %Taint(op2)));
  %Untaint(op2);
  assertEquals(res, %Taint(op1) + op2, comment);
  %Untaint(op1);
  assertEquals(res, op1 + %Taint(op2), comment);
  %Untaint(op2);
  %Untaint(op2);
}

assertTaintEquals("ab", "a", "b", "ll");

assertTaintEquals("12", "1", "2", "dd");
assertTaintEquals("123", "1", "2" + "3", "ddd");
assertTaintEquals("123", 1, "2" + "3", "ndd");
assertTaintEquals("123", "1", 2 + "3", "dnd");
assertTaintEquals("123", "1", "2" + 3, "ddn");

assertTaintEquals("123", "1" + 2, 3, "dnn");
assertTaintEquals("123", 1, "2" + 3, "ndn");
assertTaintEquals("33", 1 + 2, "3", "nnd");

var x = "1";
assertTaintEquals("12", x, 2, "vn");
assertTaintEquals("12", x, "2", "vd");
assertTaintEquals("21", 2, x, "nv");
assertTaintEquals("21", "2", x, "dv");

var y = "2";
assertTaintEquals("12", x, y, "vdvd");

x = 1;
assertTaintEquals("12", x, y, "vnvd");

y = 2;
assertTaintEquals(3, x, y, "vnvn");

x = "1";
assertTaintEquals("12", x, y, "vdvn");

y = "2";
assertTaintEquals("12", x, y, "vdvd2");

(function(x, y) {
  var z = "3";
  var w = "4";

  assertTaintEquals("11", x, x, "xx");
  assertTaintEquals("12", x, y, "xy");
  assertTaintEquals("13", x, z, "xz");
  assertTaintEquals("14", x, w, "xw");

  assertTaintEquals("21", y, x, "yx");
  assertTaintEquals("22", y, y, "yy");
  assertTaintEquals("23", y, z, "yz");
  assertTaintEquals("24", y, w, "yw");

  assertTaintEquals("31", z, x, "zx");
  assertTaintEquals("32", z, y, "zy");
  assertTaintEquals("33", z, z, "zz");
  assertTaintEquals("34", z, w, "zw");

  assertTaintEquals("41", w, x, "wx");
  assertTaintEquals("42", w, y, "wy");
  assertTaintEquals("43", w, z, "wz");
  assertTaintEquals("44", w, w, "ww");

  (function(){x = 1; z = 3;})();

  assertTaintEquals(2, x, x, "x'x");
  assertTaintEquals("12", x, y, "x'y");
  assertTaintEquals(4, x, z, "x'z'");
  assertTaintEquals("14", x, w, "x'w");

  assertTaintEquals("21", y, x, "yx'");
  assertTaintEquals("22", y, y, "yy");
  assertTaintEquals("23", y, z, "yz'");
  assertTaintEquals("24", y, w, "yw");

  assertTaintEquals(4, z, x, "z'x'");
  assertTaintEquals("32", z, y, "z'y");
  assertTaintEquals(6, z, z, "z'z'");
  assertTaintEquals("34", z, w, "z'w");

  assertTaintEquals("41", w, x, "wx'");
  assertTaintEquals("42", w, y, "wy");
  assertTaintEquals("43", w, z, "wz'");
  assertTaintEquals("44", w, w, "ww");
})("1", "2");

assertTaintEquals("142", "1", new Number(%Taint(42)), "sN");
assertTaintEquals("421", new Number(%Taint(42)), "1", "Ns");
assertTaintEquals(84, new Number(%Taint(42)), new Number(%Taint(42)), "NN");

assertTaintEquals("142", "1", new String(%Taint("42")), "sS");
assertTaintEquals("421", new String(%Taint("42")), "1", "Ss");
assertTaintEquals("142", "1", new String(%Taint("42")), "sS");
assertTaintEquals("4242", new String(%Taint("42")), new String(%Taint("42")), "SS");

assertTaintEquals("1true", "1", true, "sb");
assertTaintEquals("true1", true, "1", "bs");
assertTaintEquals(2, true, true, "bs");

assertTaintEquals("1true", "1", new Boolean(%Taint(true)), "sB");
assertTaintEquals("true1", new Boolean(%Taint(true)), "1", "Bs");
assertTaintEquals(2, new Boolean(%Taint(true)), new Boolean(%Taint(true)), "Bs");

assertTaintEquals("1undefined", "1", void 0, "sv");
assertTaintEquals("undefined1", (void 0) , "1", "vs");
assertTrue(isNaN(void 0, void 0), "vv");

assertTaintEquals("1null", "1", null, "su");
assertTaintEquals("null1", null, "1", "us");
assertTaintEquals(0, null, null, "uu");

(function (i) {
  // Check that incoming frames are merged correctly.
  var x;
  var y;
  var z;
  var w;
  switch (i) {
  case 1: x = %Taint(42); y = %Taint("stry"); z = %Taint("strz"); w = %Taint(42); break;
  default: x = %Taint("strx"), y = %Taint(42); z = %Taint("strz"); w = %Taint(42); break;
  }
  var resxx = x + x;
  var resxy = x + y;
  var resxz = x + z;
  var resxw = x + w;
  var resyx = y + x;
  var resyy = y + y;
  var resyz = y + z;
  var resyw = y + w;
  var reszx = z + x;
  var reszy = z + y;
  var reszz = z + z;
  var reszw = z + w;
  var reswx = w + x;
  var reswy = w + y;
  var reswz = w + z;
  var resww = w + w;
  assertEquals(84, resxx, "swxx");
  assertEquals("42stry", resxy, "swxy");
  assertEquals("42strz", resxz, "swxz");
  assertEquals(84, resxw, "swxw");
  assertEquals("stry42", resyx, "swyx");
  assertEquals("strystry", resyy, "swyy");
  assertEquals("strystrz", resyz, "swyz");
  assertEquals("stry42", resyw, "swyw");
  assertEquals("strz42", reszx, "swzx");
  assertEquals("strzstry", reszy, "swzy");
  assertEquals("strzstrz", reszz, "swzz");
  assertEquals("strz42", reszw, "swzw");
  assertEquals(84, reswx, "swwx");
  assertEquals("42stry", reswy, "swwy");
  assertEquals("42strz", reswz, "swwz");
  assertEquals(84, resww, "swww");
})(1);

// Generate ascii and non ascii strings from length 0 to 20.
var ascii = %Taint('aaaaaaaaaaaaaaaaaaaa');
var non_ascii = %Taint('\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234\u1234');
assertEquals(20, ascii.length);
assertEquals(20, non_ascii.length);
var a = %Taint(Array(21));
var b = %Taint(Array(21));
for (var i = 0; i <= 20; i++) {
  a[i] = ascii.substring(0, i);
  b[i] = non_ascii.substring(0, i);
}

// Add ascii and non-ascii strings generating strings with length from 0 to 20.
for (var i = 0; i <= 20; i++) {
  for (var j = 0; j < i; j++) {
    assertEquals(a[i], a[j] + a[i - j])
    assertEquals(b[i], b[j] + b[i - j])
  }
}
