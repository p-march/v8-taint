JITed Taint Tracking in V8

This repository contains a fork of V8 revision 10182 that implements JIT-enabled
dynamic taint analysis. A programmer may taint or label any data item within its
program, and our dynamic taint analysis system propagates the taint to any data
that is derived from tainted item. We allow tainting primitive data types such
as integers and strings, as well as compound data types such as JS objects. The
taint propagation takes place at every operation on a data item, e.g., an
arithmetic operation, a string operation. If any argument of operation is
tainted the result gets tainted as well. Please see details in the paper
jstaint.pdf (TODO: add the paper to repo).

To our knowledge, this is the first implementation of dynamic taint analysis in
Just-In-Time JavaScript compiler.

Generally, dynamic taint analysis used to observe data propagation within an
application. A programmer taints data items of particular interest at data
sources and then verifies if the taint data appears on specific data sinks. The
programmer may enforce different policies on the data syncs where a policy may
take different actions depending on whether it observes taint or untainted data.

The work on the taint-enabled V8 is not finished. It supports only the x64
(x86-64) architecture, although there are some modifications to x86 (x86-32)
specific files in the repository. The effort on the x86 architecture was
abandoned long time ago, and we focused only on x64.

Build with gyp:
make dependencies
make x64.debug

Run tests built with gyp:
make x64.debug.check

Run shell built with gyp:
/out/x64.debug/shell --allow_natives_syntax --taint_policy

Build with scons (scons must be pre-installed):
./tools/test.py --mode=debug --arch=x64 --build-only

Run tests built with scons:
./tools/test.py --mode=debug --arch=x64

Run debug shell built with scons:
./d8_g --allow_natives_syntax --taint_policy

Replace "debug" with "release" to build and run tests in release mode.

--taint_policy enables dynamic taint analysis.
--allow_natives is required to allow taint policy specified in ./taint_policy.js
file to taint data using %Taint().
--taint_policy_file=filename.js can be used to specify alternative file with
taint policy. By default V8 will attempt to read policy from "taint_policy.js".

Taint-enabled V8 reads a taint policy specified in taint_policy.js file. Please
see the following repository for an example of the taint_policy.js. TODO: add
the reference to repository.

An interesting optimization within taint-enabled V8 is non-taint specialization.
This optimization is possible due to the JITed nature of taint analysis. It
relies on an assumption that there should be significantly less tainted data
than non-tainted data. Thus, when we emit native code for a JS function, we
assume that this function will operate strictly with non-tainted data, and
produce native code that lacks all taint propagation routines, similarly to the
unmodified V8. Thus, this function cannot process tainted data! If tainted data
supplied to this function, V8 traps into runtime and emits another native
version of the function which does have taint propagation routines embedded. The
latter version of the function is able to processes tainted data with the cost
of executing taint propagation code. Note that there is some taint propagation
overhead even in the case when the taint-enabled function processes non-tainted
data as it still needs to perform a type check on arguments at every operation
(to check if the arguments are tainted).

The above optimization allows to run JavaScript code at no cost as soon as the
code does not encounter tainted data.
