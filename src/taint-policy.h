// Copyright 2012 the V8 project authors. All rights reserved.
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

#ifndef V8_TAINT_POLICY_H_
#define V8_TAINT_POLICY_H_

namespace v8 {
namespace internal {


class TaintPolicy : public AllStatic {
 public:
  enum PolicyAction {
    kDefault = 0,
    kAllowResult,
    kTaintResult,
    kIgnoreResult,
    kThrowException,
    kInvalid
  };

  enum OperationType {
    kCall = 0,
    kGet,
    kSet,
    kDel,
    kConstruct
  };

  static inline PolicyAction GetPolicyAction(Object* result) {
    if (!result->IsSmi())
      return kInvalid;
    switch (Smi::cast(result)->value()) {
    case kDefault:
      return kDefault;
    case kAllowResult:
      return kAllowResult;
    case kTaintResult:
      return kTaintResult;
    case kIgnoreResult:
      return kIgnoreResult;
    case kThrowException:
      return kThrowException;
    }
    return kInvalid;
  }

  static inline OperationType GetOperationType(Object* op) {
    ASSERT(op->IsSmi());

    switch (Smi::cast(op)->value()) {
    case kCall:
      return kCall;
    case kGet:
      return kGet;
    case kSet:
      return kSet;
    case kDel:
      return kDel;
    case kConstruct:
      return kConstruct;
    }
  }

  static inline PolicyAction GetDefaultPolicyAction(
      Vector< Handle<Object> >& args);

  static inline PolicyAction CombinePolicyActions(PolicyAction before,
                                                  PolicyAction after) {
    if (before == kThrowException || after == kThrowException) {
      return kThrowException;
    }

    if (before == kIgnoreResult || after == kIgnoreResult) {
      return kIgnoreResult;
    }

    if (before == kTaintResult || after == kTaintResult) {
      return kTaintResult;
    }

    if (before == kAllowResult && after == kAllowResult) {
      return kAllowResult;
    }

    return kInvalid;
  }

  static inline bool HasTaintedArguments(Vector< Handle<Object> >& args) {
    for (int i = 2; i < args.length(); i++) {
      if (args[i]->IsTainted()) {
        return true;
      }
    }
    return false;
  }

  static inline bool HasTaintedArgumentsButHolder(Vector< Handle<Object> >& args) {
    for (int i = 3; i < args.length(); i++) {
      if (args[i]->IsTainted()) {
        return true;
      }
    }
    return false;
  }

  static inline bool IsHolderTainted(Vector< Handle<Object> >& args) {
    return args[2]->IsTainted();
  }

  static inline void UntaintArguments(Arguments& args) {
    for (int i = 0; i < args.length(); i++) {
      if (args[i]->IsTainted()) {
        args[i] = Tainted::cast(args[i])->tainted_object();
      }
    }
  }

  static inline void UntaintArguments(Vector< Handle<Object> >& args) {
    for (int i = 0; i < args.length(); i++) {
      if (args[i]->IsTainted()) {
        args[i] =
          Handle<Object>(Handle<Tainted>::cast(args[i])->tainted_object());
      }
    }
  }

  static inline void BackArgumentsWithHandles(Arguments& args,
                                       Vector< Handle<Object> >& back_holder) {
    ASSERT(args.length() == back_holder.length());
    for (int i = 0; i < args.length(); i++) {
      back_holder[i] = Handle<Object>(args[i]);
    }
  }

  static inline void ResetArgumentsFromHandles(Arguments& args,
                                       Vector< Handle<Object> >& back_holder) {
    ASSERT(args.length() == back_holder.length());
    for (int i = 0; i < args.length(); i++) {
      args[i] = *back_holder[i];
    }
  }

  static MaybeObject* TaintPolicyAction(Isolate* isolate,
                                        Vector< Handle<Object> >& args,
                                        Object* before,
                                        Object* after);

  static MaybeObject* BeforeTaintPolicyAction(Isolate* isolate,
                                              Vector< Handle<Object> >& args,
                                              Object* before);

  // Checks taint policy for a particular object
  // args[0] - type of operation ('get', 'set', 'call', 'construct'
  // args[1] - holder (object the operation is being performed on)
  // args[2] - name (for 'get'/'set' name of the method, for
  // 'call'/construct' name of the function)
  // args[3] - value 0 (argument to the operation)
  // args[4] - value 1 (argument to the operation)
  // ....
  //
  // If the return value is 'true' object, in case of 'get' the result
  // of operation will be tainted, for other operations this means
  // assert the operation. If the return value is 'false' object,
  // do not taint the result of 'get' operations and do perform the
  // 'call', 'set', 'construct' operations. The return value can be
  // set to 'null' object, which enforces the default policy: do
  // not taint the result of 'get' operation, and assert the
  // 'set'/'call'/'construct' operation only if any of the
  // arguments is tainted.
  static MaybeObject* BeforeTaintPolicyCheck(Isolate* isolate,
                                             Vector< Handle<Object> >& args);
  static MaybeObject* AfterTaintPolicyCheck(Isolate* isolate,
                                            Vector< Handle<Object> >& args);
};


} }  // namespace v8::internal

#endif  // V8_TAINT_POLICY_H_
