// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './pkg/hello_world';`
// will work here one day as well!
const rust = import('./bp7');

function benchmark(bp7) {
    var runs = 100000;
    console.log("creating 0: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 0); }) + " bundles/second");
    console.log("creating 0: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 0); }) + " bundles/second");
    console.log("creating 0: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 0); }) + " bundles/second");
    console.log("creating 0: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 0); }) + " bundles/second");

    console.log("creating 1: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 1); }) + " bundles/second");
    console.log("creating 1: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 1); }) + " bundles/second");
    console.log("creating 1: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 1); }) + " bundles/second");
    console.log("creating 1: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 1); }) + " bundles/second");

    console.log("creating 2: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 2); }) + " bundles/second");
    console.log("creating 2: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 2); }) + " bundles/second");
    console.log("creating 2: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 2); }) + " bundles/second");
    console.log("creating 2: " + do_benchmark(function () { var bundle = bp7.get_encoded_bundle_with_time(Math.floor(Date.now() / 1000), 2); }) + " bundles/second");

    console.log("encoding 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 0); }) + " bundles/second");
    console.log("encoding 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 0); }) + " bundles/second");
    console.log("encoding 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 0); }) + " bundles/second");
    console.log("encoding 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 0); }) + " bundles/second");

    console.log("encoding 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 1); }) + " bundles/second");
    console.log("encoding 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 1); }) + " bundles/second");
    console.log("encoding 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 1); }) + " bundles/second");
    console.log("encoding 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 1); }) + " bundles/second");

    console.log("encoding 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 2); }) + " bundles/second");
    console.log("encoding 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 2); }) + " bundles/second");
    console.log("encoding 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 2); }) + " bundles/second");
    console.log("encoding 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_encode(runs, 2); }) + " bundles/second");

    console.log("loading 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 0); }) + " bundles/second");
    console.log("loading 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 0); }) + " bundles/second");
    console.log("loading 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 0); }) + " bundles/second");
    console.log("loading 0: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 0); }) + " bundles/second");

    console.log("loading 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 1); }) + " bundles/second");
    console.log("loading 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 1); }) + " bundles/second");
    console.log("loading 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 1); }) + " bundles/second");
    console.log("loading 1: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 1); }) + " bundles/second");

    console.log("loading 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 2); }) + " bundles/second");
    console.log("loading 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 2); }) + " bundles/second");
    console.log("loading 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 2); }) + " bundles/second");
    console.log("loading 2: " + do_bench_all(runs, function () { var bundle = bp7.benchmark_bundle_load(runs, 2); }) + " bundles/second");



}

function do_benchmark(myfunc) {
    var runs = 100000;
    var start_time = Date.now();
    for (let index = 0; index < runs; index++) {
        myfunc();
    }
    var end_time = Date.now();
    var run_time = (end_time - start_time) / 1000;
    return Math.floor(runs / run_time);
}

function do_bench_all(runs, myfunc) {
    var start_time = Date.now();
    myfunc();

    var end_time = Date.now();
    var run_time = (end_time - start_time) / 1000;
    return Math.floor(runs / run_time);
}
rust
    .then(m => m.greet('World!'))
    .catch(console.error);

rust
    .then(m => benchmark(m))
    .catch(console.error);

/*rust
    .then(m => m.do_benchmark_stuff())
    .catch(console.error);*/