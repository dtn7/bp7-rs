#include "bp7.h"
#include <stdio.h>

int main() {
  printf("bp7 c ffi test\n");

  // for (int i = 0; i < 100000; i++) {
  printf("generating random bundle...\n");
  Buffer buf = helper_rnd_bundle();

  printf("received buffer len: %ld\n", buf.len);

  printf("parsing bundle again from cbor buffer...\n");
  Bundle *bndl = bundle_from_cbor(buf);

  printf("getting metadata from parsed bundle...\n");
  BundleMetaData meta = bundle_get_metadata(bndl);
  printf(" meta.src: %s\n", meta.src);
  printf(" meta.dst: %s\n", meta.dst);
  bundle_metadata_free(meta);

  printf("getting payload from parsed bundle...\n");
  Buffer payload = bundle_payload(bndl);
  printf(" payload: %s\n", payload.data);

  buffer_free(payload);

  bundle_free(bndl);
  buffer_free(buf);
  //}
  return 0;
}