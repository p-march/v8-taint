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

#include "v8.h"

#include "arguments.h"
#include "taint-policy.h"

namespace v8 {
namespace internal {


MaybeObject* TaintPolicy::BeforeTaintPolicyCheck(Isolate* isolate,
    Vector< Handle<Object> >& args) {
  ASSERT(isolate->context()->TaintPolicyIsEnabled());
  ASSERT(args.length() >= 3);
    
  bool has_exception = false;
  MaybeObject* result = Smi::FromInt(kDefault);
  Context* current_context = isolate->context();
  Handle<Object> taint_global(current_context->GetTaintPolicyContext()->global());

  TaintDisabledContextScope ctx_scope(current_context);

  do {
    if (Handle<Smi>::cast(args[1])->value() == kConstruct) {
      // TODO(petr): for construct operation, we cannot perform check here, as
      // the object is not initialized yet and access to its members (checking its
      // taint policy function) can cause a segmentation fault in chrome.
      // The right way to do it, is to allow construct call to happen, and then
      // perform a policy check before returning the constructed object
      break;
    }
  
    Handle<Object> holder = args[2];
    Handle<String> name = isolate->factory()->taint_before_functions();

    // check if there are taint policy functions installed on the holder
    MaybeObject* maybe_obj = holder->IsTainted() ?
          Handle<Tainted>::cast(holder)->tainted_object()->GetProperty(*name) :
          holder->GetProperty(*name);
    if (maybe_obj->IsFailure()) return maybe_obj;
    Object* value = maybe_obj->ToObjectUnchecked();
  
    // leave if the policy functions set to null for the object
    // this means that the default action should be invoked
    if (value == isolate->heap()->null_value()) {
      break;
    }
  
    if (value == isolate->heap()->undefined_value()) {
      // call into policy engine to get the policy functions
      // set for the holder
      name = isolate->factory()->taint_engine();
      maybe_obj = taint_global->GetProperty(*name);
      if (maybe_obj->IsFailure()) return maybe_obj;
      value = maybe_obj->ToObjectUnchecked();
      if (!value->IsJSFunction()) {
        return isolate->Throw(*isolate->factory()->NewError(
            isolate->factory()->LookupAsciiSymbol(
            "TaintPolicyEngine() is missing")));
      }
    
      Handle<JSFunction> func = Handle<JSFunction>(JSFunction::cast(value));
      Handle<Object> retval = Execution::Call(func,
                                              taint_global,
                                              args.length(),
                                              args.start(),
                                              &has_exception);
      if (has_exception) {
        ASSERT(retval.is_null());
        return Failure::Exception();;
      }

      result = *retval;
      break;
    }

    name = isolate->factory()->taint_run_before_functions();
    maybe_obj = taint_global->GetProperty(*name);
    if (maybe_obj->IsFailure() ||
        !maybe_obj->ToObjectUnchecked()->IsJSFunction()) {
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "RunTaintPolicyBeforeFunctions() is missing")));
    }

    Handle<JSFunction> func = Handle<JSFunction>(
        JSFunction::cast(maybe_obj->ToObjectUnchecked()));
    Handle<Object> retval = Execution::Call(func,
                                            taint_global,
                                            args.length(),
                                            args.start(),
                                            &has_exception);
    if (has_exception) {
      ASSERT(retval.is_null());
      return Failure::Exception();;
    }

    result = *retval;
    break;

  } while (0);

  return result;
}


MaybeObject* TaintPolicy::AfterTaintPolicyCheck(Isolate* isolate,
    Vector< Handle<Object> >& args) {
  ASSERT(isolate->context()->TaintPolicyIsEnabled());
  ASSERT(args.length() >= 3);
    
  bool has_exception = false;
  MaybeObject* result = Smi::FromInt(kDefault);
  Context* current_context = isolate->context();
  Handle<Object> taint_global(current_context->GetTaintPolicyContext()->global());

  TaintDisabledContextScope ctx_scope(current_context);

  do {
    if (Handle<Smi>::cast(args[1])->value() == kConstruct) {
      // TODO(petr): for construct operation, we cannot perform check here, as
      // the object is not initialized yet and access to its members (checking its
      // taint policy function) can cause a segmentation fault in chrome.
      // The right way to do it, is to allow construct call to happen, and then
      // perform a policy check before returning the constructed object
      break;
    }
  
    Handle<Object> holder = args[2];
    Handle<String> name = isolate->factory()->taint_after_functions();
  
    // check if there are taint policy functions installed on the holder
    MaybeObject* maybe_obj = holder->IsTainted() ?
          Handle<Tainted>::cast(holder)->tainted_object()->GetProperty(*name) :
          holder->GetProperty(*name);
    if (maybe_obj->IsFailure()) return maybe_obj;
    Object* value = maybe_obj->ToObjectUnchecked();
  
    // leave if the policy function is null for the object
    if (value == isolate->heap()->null_value()) {
      break;
    }

    name = isolate->factory()->taint_run_after_functions();
    maybe_obj = taint_global->GetProperty(*name);
    if (maybe_obj->IsFailure() ||
        !maybe_obj->ToObjectUnchecked()->IsJSFunction()) {
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "RunTaintPolicyAfterFunctions() is missing")));
    }

    // call holder's policy function
    Handle<JSFunction> func = Handle<JSFunction>(
        JSFunction::cast(maybe_obj->ToObjectUnchecked()));
    Handle<Object> retval = Execution::Call(func,
                                            taint_global,
                                            args.length(),
                                            args.start(),
                                            &has_exception);
    if (has_exception) {
      return Failure::Exception();;
    }

    result = *retval;
    break;

  } while (0);

  return result;
}


TaintPolicy::PolicyAction TaintPolicy::GetPolicyAction(Isolate *isolate,
                                                       Object* result) {
  if (result == isolate->heap()->undefined_value()) {
    return kDefault;
  }

  if (!result->IsSmi())
    return kInvalid;

  int value = Smi::cast(result)->value();

  switch (value) {
  case kDefault:
    return kDefault;
  case kNone:
    return kNone;
  case kIgnoreResult:
    return kIgnoreResult;
  case kThrowException:
    return kThrowException;
  }

  if (value & ~(kTaintHolder | kTaintResult))
    return kInvalid;

  return value;
}


TaintPolicy::PolicyAction TaintPolicy::GetPolicyAction(Isolate *isolate,
                                                       Object* before_result,
                                                       Object* after_result) {
  PolicyAction before = GetPolicyAction(isolate, before_result);
  PolicyAction after = GetPolicyAction(isolate, after_result);

  if (before == kInvalid || after == kInvalid) {
    return kInvalid;
  }

  if (before == kThrowException || after == kThrowException) {
    return kThrowException;
  }

  if (before == kIgnoreResult || after == kIgnoreResult) {
    return kIgnoreResult;
  }

  if (before & (kTaintResult | kTaintHolder) ||
      after & (kTaintResult | kTaintHolder)) {
    return (before | after) & (kTaintResult | kTaintHolder);
  }

  if (before == kNone || after == kNone) {
    return kNone;
  }

  if (before == kDefault && after == kDefault) {
    return kDefault;
  }

  return kInvalid;
}


MaybeObject* TaintPolicy::DefaultTaintPolicyAction(Vector< Handle<Object> >& args) {
  if (HasTaintedObjectArguments(args)) {
    if (!args[2]->IsTainted() && !args[2]->HasTaintedWrapper()) {
      USE(args[2]->Taint());
    }
    if (!args[0]->IsTainted() && !args[0]->HasTaintedWrapper()) {
      return args[0]->Taint();
    }
  }
  return *args[0];
}


MaybeObject* TaintPolicy::BeforeTaintPolicyAction(Isolate* isolate,
                                                  Vector< Handle<Object> >& args,
                                                  Object* before) {
  PolicyAction action = GetPolicyAction(isolate, before);

  if (action & kInvalid) {
      ASSERT(0);
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "invalid return value in a taint function")));
  }

  if (action & kThrowException) {
    return isolate->Throw(*isolate->factory()->NewError("taint_policy", args));
  }

  if (action & kIgnoreResult) {
    return isolate->heap()->undefined_value();
  }

  if (action & kTaintHolder) {
    if (!args[2]->IsTainted() && !args[2]->HasTaintedWrapper()) {
      USE(args[2]->Taint());
    }
  }

  return isolate->heap()->null_value();
}


MaybeObject* TaintPolicy::TaintPolicyAction(Isolate* isolate,
                                            Vector< Handle<Object> >& args,
                                            Object* before,
                                            Object* after) {
  PolicyAction action = GetPolicyAction(isolate, before, after);

  if (action == kInvalid) {
      ASSERT(0);
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "invalid return value in a taint function")));
  }

  if (action == kThrowException) {
    return isolate->Throw(*isolate->factory()->NewError("taint_policy", args));
  }

  if (action == kIgnoreResult) {
    return isolate->heap()->undefined_value();
  }

  if (action == kNone) {
    return *args[0];
  }

  if (action == kDefault) {
    return DefaultTaintPolicyAction(args);
  }

  if (action & kTaintHolder) {
    if (!args[2]->IsTainted() && !args[2]->HasTaintedWrapper()) {
      USE(args[2]->Taint());
    }
  }

  if (action & kTaintResult) {
    if (!args[0]->IsTainted() && !args[0]->HasTaintedWrapper()) {
      return args[0]->Taint();
    }
  }

  return *args[0];
}


} }  // namespace v8::internal
