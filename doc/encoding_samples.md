# Bundle Protocol Version 7 CBOR Encoding Samples

**Table of Contents**

  * [Data Structures](#data-structures)
    + [Creation Timestamp](#creation-timestamp)
    + [Endpoint ID](#endpoint-id)
      - [dtn scheme](#dtn-scheme)
      - [ipn scheme](#ipn-scheme)
      - [none endpoint](#none-endpoint)
  * [Blocks](#blocks)
    + [Primary Block](#primary-block)
    + [Canonical Blocks](#canonical-blocks)
      - [Payload Block](#payload-block)
      - [Hop Count Block](#hop-count-block)
      - [Bundle Age Block](#bundle-age-block)
      - [Previous Node Block](#previous-node-block)
  * [Administrative Records](#administrative-records)
  * [Bundles](#bundles)

---

## Data Structures

### Creation Timestamp

Description | Value
--- | ---
human-readable | `2020-03-13T12:41:18Z 0`
json | `[637418478,0]`
hex string | [`821a25fe3bee00`](http://cbor.me/?bytes=821a25fe3bee00)
byte array | `[130, 26, 37, 254, 59, 238, 0]`

--- 

### Endpoint ID

#### dtn scheme

Description | Value
--- | ---
human-readable | `dtn://node1/test`
json | `[1,"node1/test"]`
hex string | [`82016a6e6f6465312f74657374`](http://cbor.me/?bytes=82016a6e6f6465312f74657374)
byte array | `[130, 1, 106, 110, 111, 100, 101, 49, 47, 116, 101, 115, 116]`

#### ipn scheme

Description | Value
--- | ---
human-readable | `ipn://23.42`
json | `[2,[23,42]]`
hex string | [`82028217182a`](http://cbor.me/?bytes=82028217182a)
byte array | `[130, 2, 130, 23, 24, 42]`

#### none endpoint

Description | Value
--- | ---
human-readable | `dtn://none`
json | `[1,0]`
hex string | [`820100`](http://cbor.me/?bytes=820100)
byte array | `[130, 1, 0]`

---

## Blocks

### Primary Block

#### No CRC

Description | Value
--- | ---
human-readable | primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, no crc
json | `[7,0,0,[1,"n2/inbox"],[1,"n1"],[1,"n1"],[2342,2],60000000]`
hex string | [`880700008201686e322f696e626f788201626e318201626e3182190926021a03938700`](http://cbor.me/?bytes=880700008201686e322f696e626f788201626e318201626e3182190926021a03938700)
byte array | `[136, 7, 0, 0, 130, 1, 104, 110, 50, 47, 105, 110, 98, 111, 120, 130, 1, 98, 110, 49, 130, 1, 98, 110, 49, 130, 25, 9, 38, 2, 26, 3, 147, 135, 0]`

#### CRC 16

Description | Value
--- | ---
human-readable | primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, crc16
json | `[7,0,1,[1,"n2/inbox"],[1,"n1"],[1,"n1"],[2342,2],60000000,[231,202]]`
hex string | [`890700018201686e322f696e626f788201626e318201626e3182190926021a0393870042e7ca`](http://cbor.me/?bytes=890700018201686e322f696e626f788201626e318201626e3182190926021a0393870042e7ca)
byte array | `[137, 7, 0, 1, 130, 1, 104, 110, 50, 47, 105, 110, 98, 111, 120, 130, 1, 98, 110, 49, 130, 1, 98, 110, 49, 130, 25, 9, 38, 2, 26, 3, 147, 135, 0, 66, 231, 202]`

#### CRC 32

Description | Value
--- | ---
human-readable | primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, crc32
json | `[7,0,2,[1,"n2/inbox"],[1,"n1"],[1,"n1"],[2342,2],60000000,[202,79,195,104]]`
hex string | [`890700028201686e322f696e626f788201626e318201626e3182190926021a0393870044ca4fc368`](http://cbor.me/?bytes=890700028201686e322f696e626f788201626e318201626e3182190926021a0393870044ca4fc368)
byte array | `[137, 7, 0, 2, 130, 1, 104, 110, 50, 47, 105, 110, 98, 111, 120, 130, 1, 98, 110, 49, 130, 1, 98, 110, 49, 130, 25, 9, 38, 2, 26, 3, 147, 135, 0, 68, 202, 79, 195, 104]`

---

### Canonical Blocks

#### Payload Block
Description | Value
--- | ---
human-readable | payload block with no flags and `'ABC'` as content, no crc
json | `[1,1,0,0,[65,66,67]]`
hex string | [`850101000043414243`](http://cbor.me/?bytes=850101000043414243)
byte array: | `[133, 1, 1, 0, 0, 67, 65, 66, 67]`


#### Hop Count Block

Description | Value
--- | ---
human-readable | hop count block with no flags, block number 1 and hop limit = 32, no crc
json | `[10,1,0,0,[32,0]]`
hex string | [`850a01000082182000`](http://cbor.me/?bytes=850a01000082182000)
byte array | `[133, 10, 1, 0, 0, 130, 24, 32, 0]`

#### Bundle Age Block

Description | Value
--- | ---
human-readable | bundle age block with no flags, block number 2 and age = 1234us, no crc
json | `[7,2,0,0,1234]`
hex string | [`85070200001904d2`](http://cbor.me/?bytes=85070200001904d2)
byte array | `[133, 7, 2, 0, 0, 25, 4, 210]`

#### Previous Node Block

Description | Value
--- | ---
human-readable | previous node block with no flags, block number 3 and prev_node = `dtn://n1`, no crc
json | `[6,3,0,0,[1,"n1"]]`
hex string | [`85060300008201626e31`](http://cbor.me/?bytes=85060300008201626e31)
byte array | `[133, 6, 3, 0, 0, 130, 1, 98, 110, 49]`


---

## Administrative Records

---

## Bundles

#### No CRC

Description | Value
--- | ---
human-readable | bundle with no flags, no fragmentation, lifetime of `60 * 60s`, creation timestamp now from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, payload `'ABC'` and hop count block with 32 hop limit, no crc
json | `[[7,131076,0,[1,"n2/inbox"],[1,"n1"],[1,"n1"],[637421757,1],3600000000],[1,1,0,0,[65,66,67]],[10,2,0,0,[32,0]]]`
hex string | [`9f88071a00020004008201686e322f696e626f788201626e318201626e31821a25fe48bd011ad693a400850101000043414243850a02000082182000ff`](http://cbor.me/?bytes=9f88071a00020004008201686e322f696e626f788201626e318201626e31821a25fe48bd011ad693a400850101000043414243850a02000082182000ff)
byte array | `[159, 136, 7, 26, 0, 2, 0, 4, 0, 130, 1, 104, 110, 50, 47, 105, 110, 98, 111, 120, 130, 1, 98, 110, 49, 130, 1, 98, 110, 49, 130, 26, 37, 254, 72, 189, 1, 26, 214, 147, 164, 0, 133, 1, 1, 0, 0, 67, 65, 66, 67, 133, 10, 2, 0, 0, 130, 24, 32, 0, 255]`
