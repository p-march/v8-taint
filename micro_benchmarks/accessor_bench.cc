#include <v8.h>
#include <assert.h>
#include <string.h>

using namespace std;
using namespace v8;

const char* var_name = "a";
const char* prop_name = "b";
const char* meth_name = "c";


const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}


void ReportException(TryCatch* try_catch) {
  HandleScope handle_scope;
  String::Utf8Value exception(try_catch->Exception());
  const char* exception_string = ToCString(exception);
  Handle<Message> message = try_catch->Message();
  if (message.IsEmpty()) {
    // V8 didn't provide any extra information about this error; just
    // print the exception.
    printf("%s\n", exception_string);
  } else {
    // Print (filename):(line number): (message).
    String::Utf8Value filename(message->GetScriptResourceName());
    const char* filename_string = ToCString(filename);
    int linenum = message->GetLineNumber();
    printf("%s:%i: %s\n", filename_string, linenum, exception_string);
    // Print line of source code.
    String::Utf8Value sourceline(message->GetSourceLine());
    const char* sourceline_string = ToCString(sourceline);
    printf("%s\n", sourceline_string);
    // Print wavy underline (GetUnderline is deprecated).
    int start = message->GetStartColumn();
    for (int i = 0; i < start; i++) {
      printf(" ");
    }
    int end = message->GetEndColumn();
    for (int i = start; i < end; i++) {
      printf("^");
    }
    printf("\n");
    String::Utf8Value stack_trace(try_catch->StackTrace());
    if (stack_trace.length() > 0) {
      const char* stack_trace_string = ToCString(stack_trace);
      printf("%s\n", stack_trace_string);
    }
  }
}


bool ExecuteString(Handle<String> source,
                   Handle<Value> name,
                   bool print_result,
                   bool report_exceptions) {
  HandleScope handle_scope;
  TryCatch try_catch;
  Handle<Script> script = Script::Compile(source, name);
  if (script.IsEmpty()) {
    // Print errors that happened during compilation.
    if (report_exceptions)
      ReportException(&try_catch);
    return false;
  } else {
    Handle<Value> result = script->Run();
    if (result.IsEmpty()) {
      assert(try_catch.HasCaught());
      // Print errors that happened during execution.
      if (report_exceptions)
        ReportException(&try_catch);
      return false;
    } else {
      assert(!try_catch.HasCaught());
      if (print_result && !result->IsUndefined()) {
        // If all went well and the result wasn't undefined then print
        // the returned value.
        String::Utf8Value str(result);
        const char* cstr = ToCString(str);
        printf("%s\n", cstr);
      }
      return true;
    }
  }
}


Handle<String> ReadFile(const char* name) {
  FILE* file = fopen(name, "rb");
  if (file == NULL) return Handle<String>();

  fseek(file, 0, SEEK_END);
  int size = ftell(file);
  rewind(file);
   
  char* chars = new char[size + 1];
  chars[size] = '\0';
  for (int i = 0; i < size;) {
    int read = fread(&chars[i], 1, size - i, file);
    i += read;
  }
  fclose(file);
  Handle<String> result = String::New(chars, size);
  delete[] chars;
  return result;
}


Handle<Value> Load(const Arguments& args) {
  for (int i = 0; i < args.Length(); i++) {
    HandleScope handle_scope;
    String::Utf8Value file(args[i]);
    if (*file == NULL) {
      return ThrowException(String::New("Error loading file"));
    }
    Handle<String> source = ReadFile(*file);
    if (source.IsEmpty()) {
      return ThrowException(String::New("Error loading file"));
    }
    if (!ExecuteString(source, String::New(*file), false, false)) {
      return ThrowException(String::New("Error executing file"));
    }
  }
  return Undefined();
}


Handle<Value> Print(const Arguments& args) {
  bool first = true;
  for (int i = 0; i < args.Length(); i++) {
    HandleScope handle_scope;
    if (first) {
      first = false;
    } else {
      printf(" ");
    }
    String::Utf8Value str(args[i]);
    const char* cstr = ToCString(str);
    printf("%s", cstr);
  }
  printf("\n");
  fflush(stdout);
  return Undefined();

}


Handle<Value> DoNothing(const Arguments& args) {
#if 0  
  printf("DoNothing\n");
#endif  
  return Undefined();
}


Handle<Value> BenchGetter(Local<String> property, 
                          const AccessorInfo& info) {
#if 0
  String::Utf8Value utf8_name(property);
  printf("BenchGetter: method %s\n", *utf8_name);
#endif
  return Undefined();
}
    

void BenchSetter(Local<String> property,
                 Local<Value> value,
                 const AccessorInfo& info) {
#if 0
  String::Utf8Value utf8_name(property);
  String::Utf8Value utf8_value(value);
  printf("BenchSetter: method %s value %s\n", *utf8_name, *utf8_value);
#endif
}
       

int main(int argc, char* argv[]) {
  bool taint_enabled = false;
  for (int i = 0; i < argc; i++) {
    if (strlen(argv[i]) != strlen("--taint_policy"))
      continue;
    if (strcmp(argv[i], "--taint_policy") == 0)
      taint_enabled = true;
  }

  V8::SetFlagsFromCommandLine(&argc, argv, true);
  HandleScope scope;
  Handle<String> script = ReadFile("accessor_run.js");

  // Taint Policy object
  Handle<ObjectTemplate> taint_global = ObjectTemplate::New();
  taint_global->Set(String::New("print"), FunctionTemplate::New(Print));

  // Taint Policy Context
  Handle<Context> taint_context = Context::New(NULL, taint_global);
  
  // Global object
  Handle<ObjectTemplate> global = ObjectTemplate::New();
  global->Set(String::New("print"), FunctionTemplate::New(Print));
  global->Set(String::New("load"), FunctionTemplate::New(Load));

  // Set ITER for taint enabled run
  if (taint_enabled) global->Set(String::New("ITER"), Integer::New(300000));
 
  // Context
  Handle<Context> context = Context::New(NULL, global);
  context->SetTaintPolicy(taint_context);
  Context::Scope context_scope(context);
  
  // ObjectTemplate
  Handle<ObjectTemplate> bench_templ = ObjectTemplate::New();
  bench_templ->SetAccessor(String::New(prop_name), BenchGetter, BenchSetter);
  bench_templ->Set(String::New(meth_name), FunctionTemplate::New(DoNothing));

  // Object
  Handle<Object> bench = bench_templ->NewInstance();
  context->Global()->Set(String::New(var_name), bench);

  // Compile script
  TryCatch try_catch;
  Handle<Script> compiled_script = Script::Compile(script);
  if (compiled_script.IsEmpty()) {
    String::Utf8Value error(try_catch.Exception());
    printf("Error: %s\n", *error);
    return 1;
  }
  
  // Run script;
  Handle<Value> result;
  {
    TaintEnabledContextScope t_context_scope(context);
    result = compiled_script->Run();
  }
  if (result.IsEmpty()) {
    String::Utf8Value error(try_catch.Exception());
    printf("Error: %s\n", *error);
    return 1;
  }
  return 0;
}
