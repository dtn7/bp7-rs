const ffi = require('ffi-napi');

const lib = ffi.Library('libbp7', {
    bp7_working: ['int', []],
    bp7_test: ['pointer', []],
    helper_rnd_bundle: ['pointer', []],
    bundle_from_cbor: ['pointer', ['pointer']],
});


console.log("bp7 test");
try {
    console.log(lib.bp7_working());
    console.log(lib.bp7_test());
    console.log(lib.bp7_test());
    var cbor = lib.helper_rnd_bundle();
    console.log(cbor);
    var bndl = lib.bundle_from_cbor(cbor);
} catch (error) {
    console.log(error);
}
