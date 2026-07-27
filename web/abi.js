'use strict';

// The little bit of ABI encoding the interactive demo needs, and no more.
//
// The read-only dashboard gets by with hand written selectors and fixed offsets
// because every call it makes takes one static argument. The write path cannot:
// evaluate() takes an FDC proof, which is a nested tuple of seven strings, a
// bytes member and a dynamic array. So this file encodes properly rather than
// pattern matching, but it stays a few hundred lines instead of pulling in a
// wallet library, because the page has no build step and a CDN that is down at
// demo time is a demo that does not happen.
//
// One shortcut is worth naming, because it is what keeps this small. The Data
// Availability Layer already hands back response_hex, which is the ABI encoding
// of IWeb2Json.Response as a single dynamic tuple, so it begins with a 0x20
// offset word. Stripping that word yields the exact bytes the Response member of
// the proof needs, which means the page never re-encodes the attested request or
// the reading. It forwards what the FDC attested, byte for byte, which is also
// the only version that can match the Merkle root the contract checks against.

(function (root) {
  const WORD = 64; // one 32 byte word, in hex characters

  function strip0x(hex) {
    return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  }

  function padLeft(hex) {
    const body = strip0x(hex);
    if (body.length > WORD) throw new Error(`value does not fit in a word: 0x${body}`);
    return body.padStart(WORD, '0');
  }

  // Right padding to a whole number of words, which is how dynamic payloads sit.
  function padRight(hex) {
    const body = strip0x(hex);
    const remainder = body.length % WORD;
    return remainder === 0 ? body : body + '0'.repeat(WORD - remainder);
  }

  function encUint(value) {
    const n = BigInt(value);
    if (n < 0n) throw new Error('negative value in an unsigned slot');
    return padLeft(n.toString(16));
  }

  function encAddress(address) {
    const body = strip0x(address).toLowerCase();
    if (!/^[0-9a-f]{40}$/.test(body)) throw new Error(`not an address: ${address}`);
    return padLeft(body);
  }

  function encBytes32(value) {
    const body = strip0x(value).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(body)) throw new Error(`not a 32 byte value: ${value}`);
    return body;
  }

  function utf8Hex(text) {
    const bytes = new TextEncoder().encode(text);
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
  }

  // A dynamic payload is its byte length followed by the bytes, right padded.
  function encDynamic(payloadHex) {
    const body = strip0x(payloadHex).toLowerCase();
    if (body.length % 2 !== 0) throw new Error('odd length hex payload');
    return encUint(body.length / 2) + padRight(body);
  }

  const encString = (text) => encDynamic(utf8Hex(text));
  const encBytes = (hex) => encDynamic(hex);

  // Lays out a tuple whose members are all dynamic: a head of offsets, then the
  // payloads. Offsets are relative to the start of the tuple, which is what makes
  // a nested tuple encodable on its own and then spliced in.
  function encDynamicTuple(encodedMembers) {
    const headBytes = encodedMembers.length * 32;
    let offset = headBytes;
    let head = '';
    let tail = '';
    for (const member of encodedMembers) {
      head += encUint(offset);
      tail += member;
      offset += member.length / 2;
    }
    return head + tail;
  }

  // IWeb2Json.RequestBody: seven strings, in the order the interface declares
  // them. The order is load bearing, since the contract hashes this encoding and
  // compares it against the policy's binding.
  const REQUEST_BODY_FIELDS = [
    'url', 'httpMethod', 'headers', 'queryParams', 'body', 'postProcessJq', 'abiSignature',
  ];

  function encodeRequestBody(requestBody) {
    const members = REQUEST_BODY_FIELDS.map((field) => {
      const value = requestBody[field];
      if (typeof value !== 'string') {
        throw new Error(`request body field ${field} is missing`);
      }
      return encString(value);
    });
    return encDynamicTuple(members);
  }

  // Selectors, taken from out/*.json methodIdentifiers rather than retyped from
  // the signatures, so a changed argument list shows up as a failing call instead
  // of a silently wrong one.
  const SELECTOR = {
    // InstructionSender
    triggerRequestHash: '0x1612609d', // triggerRequestHash((string,string,string,string,string,string,string))
    evaluate: '0xa3c46183',           // evaluate(bytes32,address,(bytes32[],(bytes32,bytes32,uint64,uint64,(string,string,string,string,string,string,string),(bytes))))
    policyTriggerRequestHash: '0xb3d90546',
    // PolicySettlement
    settle: '0x289db4b1',             // settle(bytes32,uint8,string,bytes,bytes)
    settlementOf: '0xf1d3d381',
    // FdcHub and its fee configuration
    requestAttestation: '0x6238f354', // requestAttestation(bytes)
    fdcRequestFeeConfigurations: '0x116ea702',
    getRequestFee: '0x0a0f2476',      // getRequestFee(bytes)
    // FlareSystemsManager
    firstVotingRoundStartTs: '0xe8d0e70a',
    votingEpochDurationSeconds: '0x5a832088',
  };

  // A lone dynamic argument is encoded as an offset word pointing just past it.
  const oneDynamicArg = (selector, payload) => selector + encUint(32) + payload;

  const encodeTriggerRequestHash = (requestBody) =>
    oneDynamicArg(SELECTOR.triggerRequestHash, encodeRequestBody(requestBody));

  const encodeRequestAttestation = (abiEncodedRequest) =>
    oneDynamicArg(SELECTOR.requestAttestation, encBytes(abiEncodedRequest));

  const encodeGetRequestFee = (abiEncodedRequest) =>
    oneDynamicArg(SELECTOR.getRequestFee, encBytes(abiEncodedRequest));

  // IWeb2Json.Response, taken straight from the DA Layer.
  //
  // response_hex is abi.encode of one dynamic tuple, so its first word is the
  // 0x20 offset to the tuple body. The proof needs the body alone.
  function responseTupleFromDaLayer(responseHex) {
    const body = strip0x(responseHex).toLowerCase();
    if (body.length < WORD) throw new Error('response_hex is too short to be an attestation');
    const offset = BigInt('0x' + body.slice(0, WORD));
    if (offset !== 32n) {
      throw new Error(`unexpected response_hex layout: leading offset is ${offset}, expected 32`);
    }
    return body.slice(WORD);
  }

  // IWeb2Json.Proof: (bytes32[] merkleProof, Response data). Both members are
  // dynamic, so the tuple is a two word head of offsets followed by the payloads.
  function encodeProof(merkleProof, responseHex) {
    const nodes = merkleProof.map(encBytes32).join('');
    const merklePayload = encUint(merkleProof.length) + nodes;
    const responsePayload = responseTupleFromDaLayer(responseHex);

    return encDynamicTuple([merklePayload, responsePayload]);
  }

  // evaluate(bytes32, address, Proof): two static arguments, then an offset to
  // the proof. The head is three words, so the proof starts at 0x60.
  function encodeEvaluate(policyId, payoutTo, merkleProof, responseHex) {
    return SELECTOR.evaluate
      + encBytes32(policyId)
      + encAddress(payoutTo)
      + encUint(96)
      + encodeProof(merkleProof, responseHex);
  }

  // settle(bytes32, uint8, string, bytes, bytes): two static arguments and three
  // dynamic ones, so the head is five words and the offsets start at 0xa0.
  function encodeSettle(instructionId, status, submissionTag, data, signature) {
    const dynamicMembers = [encString(submissionTag), encBytes(data), encBytes(signature)];
    const headBytes = 5 * 32;
    let offset = headBytes;
    let head = encBytes32(instructionId) + encUint(status);
    let tail = '';
    for (const member of dynamicMembers) {
      head += encUint(offset);
      tail += member;
      offset += member.length / 2;
    }
    return SELECTOR.settle + head + tail;
  }

  // ------------------------------------------------------------------ decoding

  const wordAt = (hex, index) => strip0x(hex).slice(index * WORD, (index + 1) * WORD);
  const uintAt = (hex, index) => BigInt('0x' + wordAt(hex, index));

  root.AEGIS_ABI = {
    SELECTOR,
    strip0x,
    encUint,
    encAddress,
    encBytes32,
    encString,
    encBytes,
    encodeRequestBody,
    encodeTriggerRequestHash,
    encodeRequestAttestation,
    encodeGetRequestFee,
    responseTupleFromDaLayer,
    encodeProof,
    encodeEvaluate,
    encodeSettle,
    wordAt,
    uintAt,
  };
})(typeof window !== 'undefined' ? window : globalThis);
