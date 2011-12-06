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

// Flags: --allow-natives-syntax

function IsPrimitive(x) {
  return %_IsSpecObject(x);
}

function T(val) {
  assertTrue(%_IsTainted(val));
}

function D(a, b) {
  T(a + b); // add
  T("a" + a + b); // string add
  T(a + b + "a"); // string add
  T(a - b); // sub
  T(a * b); // mul
  T(a / b); // div
  T(a % b); // mod
  T(a | b); // bit or
  T(a & b); // bit and
  T(a ^ b); // bit xor
  T(-(%_IsTainted(a) ? a : b)); // unary minus
  T(~(%_IsTainted(a) ? a : b)); // bit not
  T(a << b); // shift left
  T(a >>> b); // arithmetic shift right
  T(a >> b); // shift right
}

function Do(a, b) {
  for (var i = 0; i < 1; i++) {
    D(%Taint(a), b);
    %Untaint(a);
    D(a, %Taint(b));
    %Untaint(b);
    D(%Taint(a), %Taint(b));
    %Untaint(a);
    %Untaint(b);
  }
}

function DoD(a, b) {
  for (var i = 0; i < 1; i++) {
    D(%DeepTaint(a), b);
    %DeepUntaint(a);
    D(a, %DeepTaint(b));
    %DeepUntaint(b);
    D(%DeepTaint(a), %DeepTaint(b));
    %DeepUntaint(a);
    %DeepUntaint(b);
  }
}

Do();
Do(1, 0);
Do(NaN, NaN);
Do(1.2, 1.3);
Do("123", "123");
Do(true, true);

// These tests fail as DeepTaint needs to be implemented
DoD(new Object(), new Object());
DoD(new String("123"), new String("123"));
DoD(new Number(123), new Number(123));
DoD(new Boolean(true), new Boolean(true));
