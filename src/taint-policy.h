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
  typedef int PolicyAction;

  static const PolicyAction kDefault        = 0;
  static const PolicyAction kNone           = 1;
  static const PolicyAction kTaintResult    = 1 << 1;
  static const PolicyAction kTaintHolder    = 1 << 2;
  static const PolicyAction kIgnoreResult   = 1 << 3;
  static const PolicyAction kThrowException = 1 << 4;
  static const PolicyAction kInvalid        = 1 << 5;

  enum OperationType {
    kCall = 0,
    kGet,
    kSet,
    kDel,
    kConstruct
  };

  static PolicyAction GetPolicyAction(Isolate *isolate, Object* result);

  static PolicyAction GetPolicyAction(Isolate *isolate,
                                      Object* before_result,
                                      Object* after_result);
  
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

  static inline void PrintArguments(Arguments& args) {
    for (int i = 0; i < args.length(); i++) {
      args[i]->ShortPrint(); printf("\n");
    }
  }

  static inline void PrintArguments(Vector< Handle<Object> >& args) {
    for (int i = 0; i < args.length(); i++) {
      args[i]->ShortPrint(); printf("\n");
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

  static MaybeObject* DefaultTaintPolicyAction(Vector< Handle<Object> >& args);

  static MaybeObject* TaintPolicyAction(Isolate* isolate,
                                        Vector< Handle<Object> >& args,
                                        Object* before,
                                        Object* after);

  static MaybeObject* BeforeTaintPolicyAction(Isolate* isolate,
                                              Vector< Handle<Object> >& args,
                                              Object* before);

  static MaybeObject* BeforeTaintPolicyCheck(Isolate* isolate,
                                             Vector< Handle<Object> >& args);

  static MaybeObject* AfterTaintPolicyCheck(Isolate* isolate,
                                            Vector< Handle<Object> >& args);
};


// TODO(petr): make something smarter
class UntaintedParamScope {
 public:
  inline UntaintedParamScope(Handle<JSObject>& self,
                             Handle<String>& name,
                             Handle<Object>& value) {
    ptr_self = NULL;
    ptr_name = NULL;
    ptr_value = NULL;

    if (self->IsTainted()) {
      ptr_self = *self;
      location_self = self.location();
      *self.location() =
          JSObject::cast(Handle<Tainted>::cast(self)->tainted_object());
    }
    
    if (name->IsTainted()) {
      ptr_name = *name;
      location_name = name.location();
      *name.location() =
          String::cast(Handle<Tainted>::cast(name)->tainted_object());
    }

    if (value->IsTainted()) {
      ptr_value = *value;
      location_value = value.location();
      *value.location() = Handle<Tainted>::cast(value)->tainted_object();
    }
  }

  inline UntaintedParamScope(Handle<JSObject>& self,
                             Handle<String>& name) {
    ptr_self = NULL;
    ptr_name = NULL;
    ptr_value = NULL;

    if (self->IsTainted()) {
      ptr_self = *self;
      location_self = self.location();
      *self.location() =
          JSObject::cast(Handle<Tainted>::cast(self)->tainted_object());
    }
    
    if (name->IsTainted()) {
      ptr_name = *name;
      location_name = name.location();
      *name.location() =
          String::cast(Handle<Tainted>::cast(name)->tainted_object());
    }
  }

  inline UntaintedParamScope(Handle<JSObject>& self,
                             Handle<Object>& value) {
    ptr_self = NULL;
    ptr_name = NULL;
    ptr_value = NULL;

    if (self->IsTainted()) {
      ptr_self = *self;
      location_self = self.location();
      *self.location() =
          JSObject::cast(Handle<Tainted>::cast(self)->tainted_object());
    }

    if (value->IsTainted()) {
      ptr_value = *value;
      location_value = value.location();
      *value.location() = Handle<Tainted>::cast(value)->tainted_object();
    }
  }

  inline UntaintedParamScope(Handle<JSObject>& self) {
    ptr_self = NULL;
    ptr_name = NULL;
    ptr_value = NULL;

    if (self->IsTainted()) {
      ptr_self = *self;
      location_self = self.location();
      *self.location() =
          JSObject::cast(Handle<Tainted>::cast(self)->tainted_object());
    }
  }

  inline ~UntaintedParamScope() {
    if (ptr_self) {
      *location_self = ptr_self;
    }
    if (ptr_name) {
      *location_name = ptr_name;
    }
    if (ptr_value) {
      *location_value = ptr_value;
    }
  }

 private:
  JSObject** location_self;
  JSObject* ptr_self;
  String* ptr_name;
  String** location_name;
  Object* ptr_value;
  Object** location_value;
};

} }  // namespace v8::internal

#endif  // V8_TAINT_POLICY_H_
