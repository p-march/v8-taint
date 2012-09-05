const taint_before_func_name = "TaintPolicyBeforeFunctions";
const taint_after_func_name = "TaintPolicyAfterFunctions";

const default_action      = 0;
const none_action         = 1;
const taint_result_action = 1 << 1;
const taint_holder_action = 1 << 2;
const ignore_action       = 1 << 3;
const throw_action        = 1 << 4;

const op_call = 0;
const op_get = 1;
const op_set = 2;
const op_del = 3;
const op_construct = 4;


function _SetFunctionsValue(name, obj, value) {
  if (%_IsTainted(obj))
    obj = %GetTaintedObject(obj);
  Object.defineProperty(obj, name,
    { value: value,
      writable: false,
      configurable: false,
      enumerable: false });
}

function _AddFunction(name, obj, func) {
  var functions = obj[name];
  if (functions == undefined || functions == null) {
    functions = new Array();
  }

  if (func in functions)
    return;
 
  functions.push(func);
  _SetFunctionsValue(name, obj, functions);
}

function AddBeforeFunction(obj, func) {
  _AddFunction(taint_before_func_name, obj, func);
}

function AddAfterFunction(obj, func) {
  _AddFunction(taint_after_func_name, obj, func);
}

function AddFunction(obj, func) {
  AddBeforeFunction(obj, func);
}

function NullTaintPolicyFunctions(holder) {
  if (holder[taint_before_func_name] == undefined)
    _SetFunctionsValue(taint_before_func_name, holder, null);
  if (holder[taint_after_func_name] == undefined)
    _SetFunctionsValue(taint_after_func_name, holder, null);
}

function _RunTaintPolicyFunctions(func, ret, operation, holder, name) {
  function add_results(res1, res2) {
    if (res1 == undefined)
      res1 = default_action;
    if (res2 == undefined)
      res2 = default_action;
    if (res1 == throw_action || res2 == throw_action)
      return throw_action;
    if (res1 == ignore_action || res2 == ignore_action)
      return ignore_action;
    if (res1 & taint_result_action ||
        res1 & taint_holder_action ||
        res2 & taint_result_action ||
        res2 & taint_holder_action) {
      res1 &= (taint_result_action | taint_holder_action);
      res2 &= (taint_result_action | taint_holder_action);
      return res1 | res2;
    }
    if (res1 == none_action || res2 == none_action)
      return none_action;
    if (res1 != default_action && res2 != default_action)
      throw "unknown action value '" + res1 + "' or '" + res2 + "'";
    return default_action;
  }

  var functions = holder[func];
  if (functions == undefined)
    return undefined;

  if (functions == null)
    return default_action;

  var result = default_action;

  Array.prototype.shift.call(arguments);
  for (var i = 0; i < functions.length; i++) {
    var tmp_result = functions[i].apply(this, arguments);
    result = add_results(result, tmp_result);
  }

  return result;
}

function RunTaintPolicyBeforeFunctions(ret, operation, holder, name) {
  Array.prototype.unshift.call(arguments, taint_before_func_name);
  return _RunTaintPolicyFunctions.apply(this, arguments);
}

function RunTaintPolicyAfterFunctions(ret, operation, holder, name) {
  Array.prototype.unshift.call(arguments, taint_after_func_name);
  return _RunTaintPolicyFunctions.apply(this, arguments);
}

function RunTaintPolicyFunctions(ret, operation, holder, name) {
  return RunTaintPolicyBeforeFunctions.apply(this, arguments);
}

function do_nothing(ret, operation, holder, name) {
  return default_action;
}


function TaintPolicyEngine(ret, operation, holder, name) {
  NullTaintPolicyFunctions(holder);
  return RunTaintPolicyFunctions.apply(this, arguments);
}
