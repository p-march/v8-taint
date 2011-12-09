// Copyright 2010 the V8 project authors. All rights reserved.
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


const SMI_MAX = (1 << 29) - 1 + (1 << 29);  // Create without overflowing.
const SMI_MIN = -SMI_MAX - 1;  // Create without overflowing.
const ONE = 1;
const ONE_HUNDRED = 100;

const OBJ_42 = new (function() {
  this.valueOf = function() { return 42; };
})();

const OBJ_T42 = new (function() {
  this.valueOf = function() { return %Taint(42); };
})();

function TestTaintUnary(func, res, op) {
  assertFalse(%_IsTainted(res));
  assertFalse(%_IsTainted(op));
  assertTrue(%_IsTainted(func(%Taint(op))));
  %Untaint(op);
  assertFalse(%_IsTainted(op));
  assertEquals(res, func(%Taint(op)));  // non-smi
  %Untaint(op);
  assertFalse(%_IsTainted(res));
  assertFalse(%_IsTainted(op));
}

function TestTaintObj(func, res) {
  assertEquals(res, func(%Taint(OBJ_42)));
  %Untaint(OBJ_42);
  TestTaintUnary(func, res, OBJ_T42);
  assertTrue(%_IsTainted(func(OBJ_T42)));
  %Untaint(OBJ_T42);
  assertEquals(res, func(OBJ_T42));
  %Untaint(OBJ_T42);
}


assertEquals(42, %Taint(OBJ_42).valueOf());
%Untaint(OBJ_42);
assertEquals(42, %Taint(OBJ_T42).valueOf());
%Untaint(OBJ_T42);
assertEquals(42, OBJ_T42.valueOf());
%Untaint(OBJ_T42);


function Add1(x) {
  return x + 1;
}

function Add100(x) {
  return x + 100;
}

function Add1Reversed(x) {
  return 1 + x;
}

function Add100Reversed(x) {
  return 100 + x;
}


TestTaintUnary(Add1, 1, 0);
TestTaintUnary(Add1Reversed, 1, 0);
TestTaintUnary(Add1, SMI_MAX + ONE, SMI_MAX);
TestTaintUnary(Add1Reversed, SMI_MAX + ONE, SMI_MAX);
TestTaintObj(Add1, 42 + ONE);
TestTaintObj(Add1Reversed, 42 + ONE);
TestTaintUnary(Add100, 100, 0);  // fast case
TestTaintUnary(Add100Reversed, 100, 0);  // fast case
TestTaintUnary(Add100, SMI_MAX + ONE_HUNDRED, SMI_MAX);
TestTaintUnary(Add100Reversed, SMI_MAX + ONE_HUNDRED, SMI_MAX);
TestTaintObj(Add100, 42 + ONE_HUNDRED);
TestTaintObj(Add100Reversed, 42 + ONE_HUNDRED);


function Sub1(x) {
  return x - 1;
}

function Sub100(x) {
  return x - 100;
}

function Sub1Reversed(x) {
  return 1 - x;
}

function Sub100Reversed(x) {
  return 100 - x;
}


TestTaintUnary(Sub1, 0, 1);
TestTaintUnary(Sub1Reversed, -1, 2);  // fast case
TestTaintUnary(Sub1, SMI_MIN - ONE, SMI_MIN);  // overflow
TestTaintUnary(Sub1Reversed, ONE - SMI_MIN, SMI_MIN);  // overflow
TestTaintObj(Sub1, 42 - ONE);  // non-smi
TestTaintObj(Sub1Reversed, ONE - 42);  // non-smi
TestTaintUnary(Sub100, 0, 100);
TestTaintUnary(Sub100Reversed, 1, 99);  // fast case
TestTaintUnary(Sub100, SMI_MIN - ONE_HUNDRED, SMI_MIN);  // overflow
TestTaintUnary(Sub100Reversed, ONE_HUNDRED - SMI_MIN, SMI_MIN);  // overflow
TestTaintObj(Sub100, 42 - ONE_HUNDRED);
TestTaintObj(Sub100Reversed, ONE_HUNDRED - 42);


function Shr1(x) {
  return x >>> 1;
}

function Shr100(x) {
  return x >>> 100;
}

function Shr1Reversed(x) {
  return 1 >>> x;
}

function Shr100Reversed(x) {
  return 100 >>> x;
}

function Sar1(x) {
  return x >> 1;
}

function Sar100(x) {
  return x >> 100;
}

function Sar1Reversed(x) {
  return 1 >> x;
}

function Sar100Reversed(x) {
  return 100 >> x;
}


TestTaintUnary(Shr1, 0, 1);
TestTaintUnary(Sar1, 0, 1);
TestTaintUnary(Shr1Reversed, 0, 2);
TestTaintUnary(Sar1Reversed, 0, 2);
TestTaintUnary(Shr1, 1610612736, SMI_MIN);
TestTaintUnary(Sar1, -536870912, SMI_MIN);
TestTaintUnary(Shr1Reversed, 1, SMI_MIN);
TestTaintUnary(Sar1Reversed, 1, SMI_MIN);
TestTaintObj(Shr1, 21);
TestTaintObj(Sar1, 21);
TestTaintObj(Shr1Reversed, 0);
TestTaintObj(Sar1Reversed, 0);
TestTaintUnary(Shr100, 6, 100);
TestTaintUnary(Sar100, 6, 100);
TestTaintUnary(Shr100Reversed, 12, 99);
TestTaintUnary(Sar100Reversed, 12, 99);
TestTaintUnary(Shr100, 201326592, SMI_MIN);
TestTaintUnary(Sar100, -67108864, SMI_MIN);
TestTaintUnary(Shr100Reversed, 100, SMI_MIN);
TestTaintUnary(Sar100Reversed, 100, SMI_MIN);
TestTaintObj(Shr100, 2);
TestTaintObj(Sar100, 2);
TestTaintObj(Shr100Reversed, 0);
TestTaintObj(Sar100Reversed, 0);


function Xor1(x) {
  return x ^ 1;
}

function Xor100(x) {
  return x ^ 100;
}

function Xor1Reversed(x) {
  return 1 ^ x;
}

function Xor100Reversed(x) {
  return 100 ^ x;
}


TestTaintUnary(Xor1, 0, 1);
TestTaintUnary(Xor1Reversed, 3, 2);
TestTaintUnary(Xor1, SMI_MIN + 1, SMI_MIN);
TestTaintUnary(Xor1Reversed, SMI_MIN + 1, SMI_MIN);
TestTaintObj(Xor1, 43);
TestTaintObj(Xor1Reversed, 43);
TestTaintUnary(Xor100, 0, 100);
TestTaintUnary(Xor100Reversed, 7, 99);
TestTaintUnary(Xor100, -1073741724, SMI_MIN);
TestTaintUnary(Xor100Reversed, -1073741724, SMI_MIN);
TestTaintObj(Xor100, 78);
TestTaintObj(Xor100Reversed, 78);

var x = 0x23; var y = 0x35;
assertEquals(0x16, x ^ y);
assertEquals(0x16, %Taint(x) ^ y);
assertEquals(0x16, x ^ %Taint(y));
assertEquals(0x16, %Taint(x) ^ %Taint(y));
assertTrue(%_IsTainted(x ^ %Taint(y)));
assertTrue(%_IsTainted(%Taint(x) ^ y));


// Bitwise not.
function BitNot(x) {
  return ~x;
}


var v = 0;
TestTaintUnary(BitNot, -1, v);
v = SMI_MIN;
TestTaintUnary(BitNot, 0x3fffffff, v);
v = SMI_MAX;
TestTaintUnary(BitNot, -0x40000000, v);


// Overflowing ++ and --.
function Inc(x) {
  x++;
  return x;
}

function Dec(x) {
  x--;
  return x;
}


v = SMI_MAX;
TestTaintUnary(Inc, 0x40000000, v);
v = SMI_MIN;
TestTaintUnary(Dec, -0x40000001, v);

// Check that comparisons of numbers separated by MIN_SMI work.

function TestTaintBinary(func, res, op1, op2) {
  assertFalse(%_IsTainted(res));
  assertFalse(%_IsTainted(op1));
  assertFalse(%_IsTainted(op2));
  assertEquals(res, func(op1, op2));
  assertEquals(res, func(%Taint(op1), op2));
  %Untaint(op1);
  assertEquals(res, func(op1, %Taint(op2)));
  %Untaint(op2);
  assertEquals(res, func(%Taint(op1), %Taint(op2)));
  %Untaint(op1);
  %Untaint(op2);
}

function Equals(x, y) {
  return x == y;
}

function StrictEquals(x, y) {
  return x === y;
}

function NotEquals(x, y) {
  return x != y;
}

function NotStrictEquals(x, y) {
  return x !== y;
}

function Greater(x, y) {
  return x > y;
}

function Less(x, y) {
  return x < y;
}

function GreaterEquals(x, y) {
  return x >= y;
}

function LessEquals(x, y) {
  return x <= y;
}


TestTaintBinary(Greater, false, SMI_MIN, 0);
TestTaintBinary(Greater, false, SMI_MIN + 1, 1);
TestTaintBinary(Greater, false, SMI_MIN + 1, 2);
TestTaintBinary(Greater, false, SMI_MIN + 2, 1);
TestTaintBinary(Less, false, 0, SMI_MIN);
TestTaintBinary(Less, true, -1, SMI_MAX);
TestTaintBinary(Less, false, SMI_MAX, -1);

// Not actually Smi operations.
// Check that relations on unary ops work.
var v = -1.2;
TestTaintBinary(Equals, true, v, v);
TestTaintBinary(StrictEquals, true, v, v);
TestTaintBinary(LessEquals, true, v, v);
TestTaintBinary(GreaterEquals, true, v, v);
TestTaintBinary(Less, false, v, v);
TestTaintBinary(Greater, false, v, v);
TestTaintBinary(NotEquals, false, v, v);
TestTaintBinary(NotStrictEquals, false, v, v);

// Right hand side of unary minus is overwritable.
function UnaryMinus(x) {
  return -x;
}

v = 1.5
TestTaintUnary(UnaryMinus, -2.25, v * v);


function Shl(x, y) {
  return x << y;
}

function Shr(x, y) {
  return x >> y;
}

function Sar(x, y) {
  return x >>> y;
}


// Smi input to bitop gives non-smi result where the rhs is a float that
// can be overwritten.
var x1 = 0x10000000;
var x2 = 0x40000002;
var x3 = 0x40000000;

TestTaintBinary(Shl, 0x40000000, x1, x2 - x3);

// Smi input to bitop gives non-smi result where the rhs could be overwritten
// if it were a float, but it isn't.
x1 = 0x10000000
x2 = 4
x3 = 2
TestTaintBinary(Shl, 0x40000000, x1, x2 - x3);


// Test shift operators on non-smi inputs, giving smi and non-smi results.
function testShiftNonSmis() {
  var pos_non_smi = 2000000000;
  var neg_non_smi = -pos_non_smi;
  var pos_smi = 1000000000;
  var neg_smi = -pos_smi;

  // Begin block A
  TestTaintBinary(Shr, pos_non_smi, pos_non_smi, 0);
  TestTaintBinary(Sar, pos_non_smi, pos_non_smi, 0);
  TestTaintBinary(Shl, pos_non_smi, pos_non_smi, 0);
  TestTaintBinary(Shr, neg_non_smi, neg_non_smi, 0);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, neg_non_smi, 0);
  TestTaintBinary(Shl, neg_non_smi, neg_non_smi, 0);
  TestTaintBinary(Shr, pos_smi, pos_smi, 0);
  TestTaintBinary(Sar, pos_smi, pos_smi, 0);
  TestTaintBinary(Shl, pos_smi, pos_smi, 0);
  TestTaintBinary(Shr, neg_smi, neg_smi, 0);
  TestTaintBinary(Sar, neg_smi + 0x100000000, neg_smi, 0);
  TestTaintBinary(Shl, neg_smi, neg_smi, 0);

  TestTaintBinary(Shr, pos_non_smi / 2, pos_non_smi, 1);
  TestTaintBinary(Sar, pos_non_smi / 2, pos_non_smi, 1);
  TestTaintBinary(Shl, -0x1194D800, pos_non_smi, 1);
  TestTaintBinary(Shr, pos_non_smi / 8, pos_non_smi, 3);
  TestTaintBinary(Sar, pos_non_smi / 8, pos_non_smi, 3);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi), 3);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi), 4);
  TestTaintBinary(Shr, pos_non_smi, (pos_non_smi + 0.5), 0);
  TestTaintBinary(Sar, pos_non_smi, (pos_non_smi + 0.5) >>> 0);
  TestTaintBinary(Shl, pos_non_smi, (pos_non_smi + 0.5), 0);
  TestTaintBinary(Shr, pos_non_smi / 2, (pos_non_smi + 0.5), 1);
  TestTaintBinary(Sar, pos_non_smi / 2, (pos_non_smi + 0.5) >>> 1);
  TestTaintBinary(Shl, -0x1194D800, (pos_non_smi + 0.5), 1);
  TestTaintBinary(Shr, pos_non_smi / 8, (pos_non_smi + 0.5), 3);
  TestTaintBinary(Sar, pos_non_smi / 8, (pos_non_smi + 0.5) >>> 3);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi + 0.5), 3);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi + 0.5), 4);

  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi), 1);

  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi) >>> 1);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi), 1);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi), 3);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi), 3);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi), 4);
  TestTaintBinary(Shr, neg_non_smi, (neg_non_smi - 0.5), 0);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_non_smi - 0.5) >>> 0);
  TestTaintBinary(Shl, neg_non_smi, (neg_non_smi - 0.5), 0);
  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi - 0.5), 1);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi - 0.5) >>> 1);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi - 0.5), 1);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi - 0.5), 3);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi - 0.5) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi - 0.5), 3);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi - 0.5), 4);

  TestTaintBinary(Shr, pos_smi / 2, (pos_smi), 1);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi) >>> 1);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi), 1);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi), 3);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi) >>> 3);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi), 3);
  TestTaintBinary(Shl, 0x73594000, (pos_smi), 5);
  TestTaintBinary(Shr, pos_smi, (pos_smi + 0.5), 0);
  TestTaintBinary(Sar, pos_smi, (pos_smi + 0.5) >>> 0);
  TestTaintBinary(Shl, pos_smi, (pos_smi + 0.5), 0);
  TestTaintBinary(Shr, pos_smi / 2, (pos_smi + 0.5), 1);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi + 0.5) >>> 1);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi + 0.5), 1);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi + 0.5), 3);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi + 0.5) >>> 3);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi + 0.5), 3);
  TestTaintBinary(Shl, 0x73594000, (pos_smi + 0.5), 5);

  TestTaintBinary(Shr, neg_smi / 2, (neg_smi), 1);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi) >>> 1);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi), 1);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi), 3);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_smi), 4);
  TestTaintBinary(Shl, -0x73594000, (neg_smi), 5);
  TestTaintBinary(Shr, neg_smi, (neg_smi - 0.5), 0);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_smi - 0.5) >>> 0);
  TestTaintBinary(Shl, neg_smi, (neg_smi - 0.5), 0);
  TestTaintBinary(Shr, neg_smi / 2, (neg_smi - 0.5), 1);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi - 0.5) >>> 1);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi - 0.5), 1);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi - 0.5), 3);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi - 0.5) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_smi - 0.5), 4);
  TestTaintBinary(Shl, -0x73594000, (neg_smi - 0.5), 5);
  // End block A

  // Repeat block A with 2^32 added to positive numbers and
  // 2^32 subtracted from negative numbers.
  // Begin block A repeat 1
  var two_32 = 0x100000000;
  var neg_32 = -two_32;
  TestTaintBinary(Shr, pos_non_smi, (two_32 + pos_non_smi), 0);
  TestTaintBinary(Sar, pos_non_smi, (two_32 + pos_non_smi) >>> 0);
  TestTaintBinary(Shl, pos_non_smi, (two_32 + pos_non_smi), 0);
  TestTaintBinary(Shr, neg_non_smi, (neg_32 + neg_non_smi), 0);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_32 + neg_non_smi) >>> 0);
  TestTaintBinary(Shl, neg_non_smi, (neg_32 + neg_non_smi), 0);
  TestTaintBinary(Shr, pos_smi, (two_32 + pos_smi), 0);
  TestTaintBinary(Sar, pos_smi, (two_32 + pos_smi) >>> 0);
  TestTaintBinary(Shl, pos_smi, (two_32 + pos_smi), 0);
  TestTaintBinary(Shr, neg_smi, (neg_32 + neg_smi), 0);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_32 + neg_smi) >>> 0);
  TestTaintBinary(Shl, neg_smi, (neg_32 + neg_smi), 0);

  TestTaintBinary(Shr, pos_non_smi / 2, (two_32 + pos_non_smi), 1);
  TestTaintBinary(Sar, pos_non_smi / 2, (two_32 + pos_non_smi) >>> 1);
  TestTaintBinary(Shl, -0x1194D800, (two_32 + pos_non_smi), 1);
  TestTaintBinary(Shr, pos_non_smi / 8, (two_32 + pos_non_smi), 3);
  TestTaintBinary(Sar, pos_non_smi / 8, (two_32 + pos_non_smi) >>> 3);
  TestTaintBinary(Shl, -0x46536000, (two_32 + pos_non_smi), 3);
  TestTaintBinary(Shl, 0x73594000, (two_32 + pos_non_smi), 4);
  TestTaintBinary(Shr, pos_non_smi, (two_32 + pos_non_smi + 0.5), 0);
  TestTaintBinary(Sar, pos_non_smi, (two_32 + pos_non_smi + 0.5) >>> 0);
  TestTaintBinary(Shl, pos_non_smi, (two_32 + pos_non_smi + 0.5), 0);
  TestTaintBinary(Shr, pos_non_smi / 2, (two_32 + pos_non_smi + 0.5), 1);
  TestTaintBinary(Sar, pos_non_smi / 2, (two_32 + pos_non_smi + 0.5) >>> 1);
  TestTaintBinary(Shl, -0x1194D800, (two_32 + pos_non_smi + 0.5), 1);
  TestTaintBinary(Shr, pos_non_smi / 8, (two_32 + pos_non_smi + 0.5), 3);
  TestTaintBinary(Sar, pos_non_smi / 8, (two_32 + pos_non_smi + 0.5) >>> 3);
  TestTaintBinary(Shl, -0x46536000, (two_32 + pos_non_smi + 0.5), 3);
  TestTaintBinary(Shl, 0x73594000, (two_32 + pos_non_smi + 0.5), 4);

  TestTaintBinary(Shr, neg_non_smi / 2, (neg_32 + neg_non_smi), 1);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_32 + neg_non_smi) >>> 1);
  TestTaintBinary(Shl, 0x1194D800, (neg_32 + neg_non_smi), 1);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_32 + neg_non_smi), 3);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_32 + neg_non_smi) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_32 + neg_non_smi), 3);
  TestTaintBinary(Shl, -0x73594000, (neg_32 + neg_non_smi), 4);
  TestTaintBinary(Shr, neg_non_smi, (neg_32 + neg_non_smi - 0.5), 0);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_32 + neg_non_smi - 0.5) >>> 0);
  TestTaintBinary(Shl, neg_non_smi, (neg_32 + neg_non_smi - 0.5), 0);
  TestTaintBinary(Shr, neg_non_smi / 2, (neg_32 + neg_non_smi - 0.5), 1);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_32 + neg_non_smi - 0.5), 1);
  TestTaintBinary(Shl, 0x1194D800, (neg_32 + neg_non_smi - 0.5), 1);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_32 + neg_non_smi - 0.5), 3);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_32 + neg_non_smi - 0.5), 3);
  TestTaintBinary(Shl, 0x46536000, (neg_32 + neg_non_smi - 0.5), 3);
  TestTaintBinary(Shl, -0x73594000, (neg_32 + neg_non_smi - 0.5), 4);

  TestTaintBinary(Shr, pos_smi / 2, (two_32 + pos_smi), 1);
  TestTaintBinary(Sar, pos_smi / 2, (two_32 + pos_smi) >>> 1);
  TestTaintBinary(Shl, pos_non_smi, (two_32 + pos_smi), 1);
  TestTaintBinary(Shr, pos_smi / 8, (two_32 + pos_smi), 3);
  TestTaintBinary(Sar, pos_smi / 8, (two_32 + pos_smi) >>> 3);
  TestTaintBinary(Shl, -0x2329b000, (two_32 + pos_smi), 3);
  TestTaintBinary(Shl, 0x73594000, (two_32 + pos_smi), 5);
  TestTaintBinary(Shr, pos_smi, (two_32 + pos_smi + 0.5), 0);
  TestTaintBinary(Sar, pos_smi, (two_32 + pos_smi + 0.5) >>> 0);
  TestTaintBinary(Shl, pos_smi, (two_32 + pos_smi + 0.5), 0);
  TestTaintBinary(Shr, pos_smi / 2, (two_32 + pos_smi + 0.5), 1);
  TestTaintBinary(Sar, pos_smi / 2, (two_32 + pos_smi + 0.5) >>> 1);
  TestTaintBinary(Shl, pos_non_smi, (two_32 + pos_smi + 0.5), 1);
  TestTaintBinary(Shr, pos_smi / 8, (two_32 + pos_smi + 0.5), 3);
  TestTaintBinary(Sar, pos_smi / 8, (two_32 + pos_smi + 0.5) >>> 3);
  TestTaintBinary(Shl, -0x2329b000, (two_32 + pos_smi + 0.5), 3);
  TestTaintBinary(Shl, 0x73594000, (two_32 + pos_smi + 0.5), 5);

  TestTaintBinary(Shr, neg_smi / 2, (neg_32 + neg_smi), 1);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_32 + neg_smi) >>> 1);
  TestTaintBinary(Shl, neg_non_smi, (neg_32 + neg_smi), 1);
  TestTaintBinary(Shr, neg_smi / 8, (neg_32 + neg_smi), 3);
  TestTaintBinary(Sar, (neg_smi + 0x100000000) / 8, (neg_32 + neg_smi) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_32 + neg_smi), 4);
  TestTaintBinary(Shl, -0x73594000, (neg_32 + neg_smi), 5);
  TestTaintBinary(Shr, neg_smi, (neg_32 + neg_smi - 0.5), 0);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_32 + neg_smi - 0.5) >>> 0);
  TestTaintBinary(Shl, neg_smi, (neg_32 + neg_smi - 0.5), 0);
  TestTaintBinary(Shr, neg_smi / 2, (neg_32 + neg_smi - 0.5), 1);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_32 + neg_smi - 0.5) >>> 1);
  TestTaintBinary(Shl, neg_non_smi, (neg_32 + neg_smi - 0.5), 1);
  TestTaintBinary(Shr, neg_smi / 8, (neg_32 + neg_smi - 0.5), 3);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_32 + neg_smi - 0.5) >>> 3);
  TestTaintBinary(Shl, 0x46536000, (neg_32 + neg_smi - 0.5), 4);
  TestTaintBinary(Shl, -0x73594000, (neg_32 + neg_smi - 0.5), 5);
  // End block A repeat 1
  // Repeat block A with shift amounts in variables intialized with
  // a constant.
  var zero = 0;
  var one = 1;
  var three = 3;
  var four = 4;
  var five = 5;
  // Begin block A repeat 2
  TestTaintBinary(Shr, pos_non_smi, (pos_non_smi), zero);
  TestTaintBinary(Sar, pos_non_smi, (pos_non_smi) >>> zero);
  TestTaintBinary(Shl, pos_non_smi, (pos_non_smi), zero);
  TestTaintBinary(Shr, neg_non_smi, (neg_non_smi), zero);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_non_smi) >>> zero);
  TestTaintBinary(Shl, neg_non_smi, (neg_non_smi), zero);
  TestTaintBinary(Shr, pos_smi, (pos_smi), zero);
  TestTaintBinary(Sar, pos_smi, (pos_smi) >>> zero);
  TestTaintBinary(Shl, pos_smi, (pos_smi), zero);
  TestTaintBinary(Shr, neg_smi, (neg_smi), zero);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_smi) >>> zero);
  TestTaintBinary(Shl, neg_smi, (neg_smi), zero);

  TestTaintBinary(Shr, pos_non_smi / 2, (pos_non_smi), one);
  TestTaintBinary(Sar, pos_non_smi / 2, (pos_non_smi) >>> one);
  TestTaintBinary(Shl, -0x1194D800, (pos_non_smi), one);
  TestTaintBinary(Shr, pos_non_smi / 8, (pos_non_smi), three);
  TestTaintBinary(Sar, pos_non_smi / 8, (pos_non_smi) >>> three);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi), three);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi), four);
  TestTaintBinary(Shr, pos_non_smi, (pos_non_smi + 0.5), zero);
  TestTaintBinary(Sar, pos_non_smi, (pos_non_smi + 0.5) >>> zero);
  TestTaintBinary(Shl, pos_non_smi, (pos_non_smi + 0.5), zero);
  TestTaintBinary(Shr, pos_non_smi / 2, (pos_non_smi + 0.5), one);
  TestTaintBinary(Sar, pos_non_smi / 2, (pos_non_smi + 0.5) >>> one);
  TestTaintBinary(Shl, -0x1194D800, (pos_non_smi + 0.5), one);
  TestTaintBinary(Shr, pos_non_smi / 8, (pos_non_smi + 0.5), three);
  TestTaintBinary(Sar, pos_non_smi / 8, (pos_non_smi + 0.5) >>> three);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi + 0.5), three);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi + 0.5), four);

  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi), one);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi) >>> one);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi), one);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi), three);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi) >>> three);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi), three);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi), four);
  TestTaintBinary(Shr, neg_non_smi, (neg_non_smi - 0.5), zero);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_non_smi - 0.5) >>> zero);
  TestTaintBinary(Shl, neg_non_smi, (neg_non_smi - 0.5), zero);
  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi - 0.5), one);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi - 0.5) >>> one);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi - 0.5), one);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi - 0.5), three);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi - 0.5), three);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi - 0.5), three);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi - 0.5), four);

  TestTaintBinary(Shr, pos_smi / 2, (pos_smi), one);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi) >>> one);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi), one);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi), three);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi) >>> three);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi), three);
  TestTaintBinary(Shl, 0x73594000, (pos_smi), five);
  TestTaintBinary(Shr, pos_smi, (pos_smi + 0.5), zero);
  TestTaintBinary(Sar, pos_smi, (pos_smi + 0.5) >>> zero);
  TestTaintBinary(Shl, pos_smi, (pos_smi + 0.5), zero);
  TestTaintBinary(Shr, pos_smi / 2, (pos_smi + 0.5), one);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi + 0.5) >>> one);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi + 0.5), one);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi + 0.5), three);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi + 0.5) >>> three);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi + 0.5), three);
  TestTaintBinary(Shl, 0x73594000, (pos_smi + 0.5), five);

  TestTaintBinary(Shr, neg_smi / 2, (neg_smi), one);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi) >>> one);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi), one);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi), three);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi) >>> three);
  TestTaintBinary(Shl, 0x46536000, (neg_smi), four);
  TestTaintBinary(Shl, -0x73594000, (neg_smi), five);
  TestTaintBinary(Shr, neg_smi, (neg_smi - 0.5), zero);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_smi - 0.5) >>> zero);
  TestTaintBinary(Shl, neg_smi, (neg_smi - 0.5), zero);
  TestTaintBinary(Shr, neg_smi / 2, (neg_smi - 0.5), one);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi - 0.5) >>> one);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi - 0.5), one);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi - 0.5), three);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi - 0.5) >>> three);
  TestTaintBinary(Shl, 0x46536000, (neg_smi - 0.5), four);
  TestTaintBinary(Shl, -0x73594000, (neg_smi - 0.5), five);
  // End block A repeat 2

  // Repeat previous block, with computed values in the shift variables.
  five = 0;
  while (five < 5 ) ++five;
  four = five - one;
  three = four - one;
  one = four - three;
  zero = one - one;

  // Begin block A repeat 3
  TestTaintBinary(Shr, pos_non_smi, (pos_non_smi), zero);
  TestTaintBinary(Sar, pos_non_smi, (pos_non_smi) >>> zero);
  TestTaintBinary(Shl, pos_non_smi, (pos_non_smi), zero);
  TestTaintBinary(Shr, neg_non_smi, (neg_non_smi), zero);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_non_smi), zero);
  TestTaintBinary(Shl, neg_non_smi, (neg_non_smi), zero);
  TestTaintBinary(Shr, pos_smi, (pos_smi), zero);
  TestTaintBinary(Sar, pos_smi, (pos_smi), zero);
  TestTaintBinary(Shl, pos_smi, (pos_smi), zero);
  TestTaintBinary(Shr, neg_smi, (neg_smi), zero);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_smi), zero);
  TestTaintBinary(Shl, neg_smi, (neg_smi), zero);

  TestTaintBinary(Shr, pos_non_smi / 2, (pos_non_smi), one);
  TestTaintBinary(Sar, pos_non_smi / 2, (pos_non_smi), one);
  TestTaintBinary(Shl, -0x1194D800, (pos_non_smi), one);
  TestTaintBinary(Shr, pos_non_smi / 8, (pos_non_smi), three);
  TestTaintBinary(Sar, pos_non_smi / 8, (pos_non_smi), three);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi), three);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi), four);
  TestTaintBinary(Shr, pos_non_smi, (pos_non_smi + 0.5), zero);
  TestTaintBinary(Sar, pos_non_smi, (pos_non_smi + 0.5), zero);
  TestTaintBinary(Shl, pos_non_smi, (pos_non_smi + 0.5), zero);
  TestTaintBinary(Shr, pos_non_smi / 2, (pos_non_smi + 0.5), one);
  TestTaintBinary(Sar, pos_non_smi / 2, (pos_non_smi + 0.5), one);
  TestTaintBinary(Shl, -0x1194D800, (pos_non_smi + 0.5), one);
  TestTaintBinary(Shr, pos_non_smi / 8, (pos_non_smi + 0.5), three);
  TestTaintBinary(Sar, pos_non_smi / 8, (pos_non_smi + 0.5), three);
  TestTaintBinary(Shl, -0x46536000, (pos_non_smi + 0.5), three);
  TestTaintBinary(Shl, 0x73594000, (pos_non_smi + 0.5), four);

  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi), one);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi), one);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi), one);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi), three);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi), three);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi), three);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi), four);
  TestTaintBinary(Shr, neg_non_smi, (neg_non_smi - 0.5), zero);
  TestTaintBinary(Sar, neg_non_smi + 0x100000000, (neg_non_smi - 0.5), zero);
  TestTaintBinary(Shl, neg_non_smi, (neg_non_smi - 0.5), zero);
  TestTaintBinary(Shr, neg_non_smi / 2, (neg_non_smi - 0.5), one);
  TestTaintBinary(Sar, neg_non_smi / 2 + 0x100000000 / 2, (neg_non_smi - 0.5), one);
  TestTaintBinary(Shl, 0x1194D800, (neg_non_smi - 0.5), one);
  TestTaintBinary(Shr, neg_non_smi / 8, (neg_non_smi - 0.5), three);
  TestTaintBinary(Sar, neg_non_smi / 8 + 0x100000000 / 8, (neg_non_smi - 0.5), three);
  TestTaintBinary(Shl, 0x46536000, (neg_non_smi - 0.5), three);
  TestTaintBinary(Shl, -0x73594000, (neg_non_smi - 0.5), four);

  TestTaintBinary(Shr, pos_smi / 2, (pos_smi), one);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi), one);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi), one);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi), three);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi), three);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi), three);
  TestTaintBinary(Shl, 0x73594000, (pos_smi), five);
  TestTaintBinary(Shr, pos_smi, (pos_smi + 0.5), zero);
  TestTaintBinary(Sar, pos_smi, (pos_smi + 0.5), zero);
  TestTaintBinary(Shl, pos_smi, (pos_smi + 0.5), zero);
  TestTaintBinary(Shr, pos_smi / 2, (pos_smi + 0.5), one);
  TestTaintBinary(Sar, pos_smi / 2, (pos_smi + 0.5), one);
  TestTaintBinary(Shl, pos_non_smi, (pos_smi + 0.5), one);
  TestTaintBinary(Shr, pos_smi / 8, (pos_smi + 0.5), three);
  TestTaintBinary(Sar, pos_smi / 8, (pos_smi + 0.5), three);
  TestTaintBinary(Shl, -0x2329b000, (pos_smi + 0.5), three);
  TestTaintBinary(Shl, 0x73594000, (pos_smi + 0.5), five);

  TestTaintBinary(Shr, neg_smi / 2, (neg_smi), one);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi), one);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi), one);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi), three);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi), three);
  TestTaintBinary(Shl, 0x46536000, (neg_smi), four);
  TestTaintBinary(Shl, -0x73594000, (neg_smi), five);
  TestTaintBinary(Shr, neg_smi, (neg_smi - 0.5), zero);
  TestTaintBinary(Sar, neg_smi + 0x100000000, (neg_smi - 0.5), zero);
  TestTaintBinary(Shl, neg_smi, (neg_smi - 0.5), zero);
  TestTaintBinary(Shr, neg_smi / 2, (neg_smi - 0.5), one);
  TestTaintBinary(Sar, neg_smi / 2 + 0x100000000 / 2, (neg_smi - 0.5), one);
  TestTaintBinary(Shl, neg_non_smi, (neg_smi - 0.5), one);
  TestTaintBinary(Shr, neg_smi / 8, (neg_smi - 0.5), three);
  TestTaintBinary(Sar, neg_smi / 8 + 0x100000000 / 8, (neg_smi - 0.5), three);
  TestTaintBinary(Shl, 0x46536000, (neg_smi - 0.5), four);
  TestTaintBinary(Shl, -0x73594000, (neg_smi - 0.5), five);
  // End block A repeat 3

  // Test non-integer shift value
  TestTaintBinary(Shr, 5, 20.5, 2.4);
  TestTaintBinary(Shr, 5, 20.5, 2.7);
  var shift = 2.4;
  TestTaintBinary(Shr, 5, 20.5, shift);
  TestTaintBinary(Shr, 5, 20.5, shift + 0.3);
  shift = shift + zero;
  TestTaintBinary(Shr, 5, 20.5, shift);
  TestTaintBinary(Shr, 5, 20.5, shift + 0.3);
}

testShiftNonSmis();

function intConversion() {
  function Conversion1(x, y) {
    return (x * y) | 0;
  }
  function Conversion2(x, y) {
    return x | y;
  }
  function foo(x) {
    TestTaintBinary(Conversion1, x, x, 1.0000000001);
    TestTaintBinary(Conversion2, x, x, 0);
    if (x > 0) {
      TestTaintBinary(Conversion1, x - 1, x, 0.9999999999);
    } else {
      TestTaintBinary(Conversion1, x + 1, x, 0.9999999999);
    }
  }
  for (var i = 1; i < 0x80000000; i *= 2) {
    foo(i);
    foo(-i);
  }
  for (var i = 1; i < 1/0; i *= 2) {
    TestTaintBinary(Conversion1, i | 0, i, 1.0000000000000001);
    TestTaintBinary(Conversion1, -i | 0, i, -1.0000000000000001);
  }
  for (var i = 0.5; i > 0; i /= 2) {
    TestTaintBinary(Conversion2, 0, i, 0);
    TestTaintBinary(Conversion2, 0, -i, 0);
  }
}

intConversion();

// Verify that we handle the (optimized) corner case of shifting by
// zero even for non-smis.
function shiftByZero(n) { return n << 0; }

TestTaintUnary(shiftByZero, 3, 3.1415);

// Verify that the static type information of x >>> 32 is computed correctly.
function LogicalShiftRightByMultipleOf32(x) {
  x = x >>> 32;
  return x + x;
}

TestTaintUnary(LogicalShiftRightByMultipleOf32, 4589934592, -2000000000);
TestTaintUnary(LogicalShiftRightByMultipleOf32, 4589934592, -2000000000);

// Verify that the shift amount is reduced modulo 32, not modulo 64.
function LeftShiftThreeBy(x) {return 3 << x;}
TestTaintUnary(LeftShiftThreeBy, 24, 3);
TestTaintUnary(LeftShiftThreeBy, 24, 35);
TestTaintUnary(LeftShiftThreeBy, 24, 67);
TestTaintUnary(LeftShiftThreeBy, 24, -29);

// Regression test for a bug in the ARM code generator.  For some register
// allocations we got the Smi overflow case wrong.
function f(x, y) { return y +  ( 1 << (x & 31)); }
TestTaintBinary(f, -2147483647, 31, 1);

// Regression test for correct handling of overflow in smi comparison.
TestTaintBinary(Less, true, -0x40000000, 42);
