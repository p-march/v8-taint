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
  ASSERT(isolate->context()->HasTaintPolicyContext());
  ASSERT(args.length() >= 3);
    
  bool has_exception = false;
  MaybeObject* result = Smi::FromInt(kDefault);
  Context* current_context = isolate->context();
  Handle<Object> taint_global(current_context->GetTaintPolicyContext()->global());

  UntaintedContextScope scope(current_context);

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
    Handle<JSFunction> func;
    Handle<String> name =
      isolate->factory()->LookupAsciiSymbol("BeforeTaintPolicyFunction");
    i::Object* func_obj;
  
    // check if there is a taint policy function installed on the holder
    // object
    i::MaybeObject* maybe_obj = holder->IsTainted() ?
          Handle<Tainted>::cast(holder)->tainted_object()->GetProperty(*name) :
          holder->GetProperty(*name);
    ASSERT(!maybe_obj->IsFailure());
    func_obj = maybe_obj->ToObjectUnchecked();
  
    // leave if the policy function is null for the object
    if (func_obj == isolate->heap()->null_value()) {
      break;
    }
  
    if (func_obj == isolate->heap()->undefined_value()) {
      // call into policy engine to get the policy function for the
      // holder object which also may be installed on the holder
      // object for future policy checks
      name = isolate->factory()->LookupAsciiSymbol("TaintPolicyEngine");
      maybe_obj = taint_global->GetProperty(*name);
      if (maybe_obj->IsFailure()) {
        return maybe_obj;
      }
      func_obj = maybe_obj->ToObjectUnchecked();
      if (!func_obj->IsJSFunction()) {
        return isolate->Throw(*isolate->factory()->NewError(
            isolate->factory()->LookupAsciiSymbol(
            "BeforeTaintPolicyEngine() is missing")));
      }
  
      func = Handle<JSFunction>(JSFunction::cast(func_obj));
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
  
    if (!func_obj->IsJSFunction()) {
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "TaintPolicyFunction() is not set properly")));
    }
  
    // call holder's policy function
    func = Handle<JSFunction>(JSFunction::cast(func_obj));
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


MaybeObject* TaintPolicy::AfterTaintPolicyCheck(Isolate* isolate,
    Vector< Handle<Object> >& args) {
  ASSERT(isolate->context()->HasTaintPolicyContext());
  ASSERT(args.length() >= 3);
    
  bool has_exception = false;
  MaybeObject* result = Smi::FromInt(kDefault);
  Context* current_context = isolate->context();
  Handle<Object> taint_global(current_context->GetTaintPolicyContext()->global());

  UntaintedContextScope scope(current_context);

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
    Handle<JSFunction> func;
    Handle<String> name =
      isolate->factory()->LookupAsciiSymbol("AfterTaintPolicyFunction");
    i::Object* func_obj;
  
    // check if there is a taint policy function installed on the holder
    // object
    i::MaybeObject* maybe_obj = holder->IsTainted() ?
          Handle<Tainted>::cast(holder)->tainted_object()->GetProperty(*name) :
          holder->GetProperty(*name);
    ASSERT(!maybe_obj->IsFailure());
    func_obj = maybe_obj->ToObjectUnchecked();
  
    // leave if the policy function is null for the object
    if (func_obj == isolate->heap()->null_value()) {
      break;
    }
  
    if (func_obj == isolate->heap()->undefined_value()) {
      break;
    }
  
    if (!func_obj->IsJSFunction()) {
      return isolate->Throw(*isolate->factory()->NewError(
          isolate->factory()->LookupAsciiSymbol(
          "AfterTaintPolicyFunction() is not set properly")));
    }
  
    // call holder's policy function
    func = Handle<JSFunction>(JSFunction::cast(func_obj));
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


MaybeObject* TaintPolicy::TaintPolicyAction(Isolate* isolate,
                                            Vector< Handle<Object> >& args,
                                            Object* before,
                                            Object* after) {
  MaybeObject* ret_val;
  PolicyAction before_action = GetPolicyAction(before);
  PolicyAction after_action = GetPolicyAction(after);

  if (before_action == TaintPolicy::kDefault) {
    before_action = TaintPolicy::GetDefaultPolicyAction(args);
  }

  if (after_action == TaintPolicy::kDefault) {
    after_action = TaintPolicy::GetDefaultPolicyAction(args);
  }

  switch(CombinePolicyActions(before_action, after_action)) {
  case TaintPolicy::kAllowResult:
    ret_val = *args[0];
    break;
  case TaintPolicy::kTaintResult:
    ret_val = (*args[0])->Taint();
    break;
  case TaintPolicy::kIgnoreResult:
    ret_val = isolate->heap()->undefined_value();
    break;
  case TaintPolicy::kThrowException:
    ret_val = isolate->Throw(
        *isolate->factory()->NewError("taint_policy", args));
    break;
  case TaintPolicy::kInvalid:
    ASSERT(0);
    ret_val = isolate->Throw(*isolate->factory()->NewError(
        isolate->factory()->LookupAsciiSymbol(
        "invalid return value in a taint function")));
    break;
  default:
    UNREACHABLE();
  }

  return ret_val;
}

MaybeObject* TaintPolicy::BeforeTaintPolicyAction(Isolate* isolate,
                                                  Vector< Handle<Object> >& args,
                                                  Object* before) {
  MaybeObject* ret_val;
  PolicyAction before_action = GetPolicyAction(before);

  if (before_action == TaintPolicy::kDefault) {
    before_action = TaintPolicy::GetDefaultPolicyAction(args);
  }

  switch(before_action) {
  case TaintPolicy::kAllowResult:
  case TaintPolicy::kTaintResult:
  case TaintPolicy::kIgnoreResult:
    ret_val = isolate->heap()->undefined_value();
    break;
  case TaintPolicy::kThrowException:
    ret_val = isolate->Throw(
        *isolate->factory()->NewError("taint_policy", args));
    break;
  case TaintPolicy::kInvalid:
    before->Print();
    ASSERT(0);
    ret_val = isolate->Throw(*isolate->factory()->NewError(
        isolate->factory()->LookupAsciiSymbol(
        "invalid return value in a taint function")));
    break;
  default:
    UNREACHABLE();
  }

  return ret_val;
}


TaintPolicy::PolicyAction TaintPolicy::GetDefaultPolicyAction(
    Vector< Handle<Object> >& args) {
  if (!HasTaintedArguments(args))
    return kAllowResult;

  if (HasTaintedArgumentsButHolder(args))
    return kThrowException;

  /* Holder is tainted and arguments are not tainted */
  OperationType op = GetOperationType(*args[1]);
  if (op == kGet || op == kCall) {
    return kTaintResult;
  }

  return kThrowException;
}


} }  // namespace v8::internal
