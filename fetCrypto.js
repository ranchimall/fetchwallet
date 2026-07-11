(function (EXPORTS) {
  "use strict";
  const fetCrypto = EXPORTS;

  // Generate a new random key
  function generateNewID() {
    var key = new Bitcoin.ECKey(false);
    key.setCompressed(true);
    return {
      floID: key.getBitcoinAddress(),
      pubKey: key.getPubKeyHex(),
      privKey: key.getBitcoinWalletImportFormat(),
    };
  }
  Object.defineProperties(fetCrypto, {
    newID: {
      get: () => generateNewID(),
    },
    hashID: {
      value: (str) => {
        let bytes = ripemd160(Crypto.SHA256(str, { asBytes: true }), {
          asBytes: true,
        });
        bytes.unshift(bitjs.pub);
        var hash = Crypto.SHA256(
          Crypto.SHA256(bytes, {
            asBytes: true,
          }),
          {
            asBytes: true,
          }
        );
        var checksum = hash.slice(0, 4);
        return bitjs.Base58.encode(bytes.concat(checksum));
      },
    },
    tmpID: {
      get: () => {
        let bytes = Crypto.util.randomBytes(20);
        bytes.unshift(bitjs.pub);
        var hash = Crypto.SHA256(
          Crypto.SHA256(bytes, {
            asBytes: true,
          }),
          {
            asBytes: true,
          }
        );
        var checksum = hash.slice(0, 4);
        return bitjs.Base58.encode(bytes.concat(checksum));
      },
    },
  });

  // --- Multi-chain Generator (BTC, FLO, AVAX) ---
  fetCrypto.generateMultiChain = async function (inputWif) {
    const versions = {
      BTC: { pub: 0x00, priv: 0x80 },
      FLO: { pub: 0x23, priv: 0xa3 },
    };

    const origBitjsPub = bitjs.pub;
    const origBitjsPriv = bitjs.priv;
    const origBitjsCompressed = bitjs.compressed;
    const origCoinJsCompressed = coinjs.compressed;

    bitjs.compressed = true;
    coinjs.compressed = true;

    let privKeyHex;
    let compressed = true;

    // --- Decode input or generate new ---
    if (typeof inputWif === "string" && inputWif.trim().length > 0) {
      const hexOnly = /^[0-9a-fA-F]+$/.test(inputWif.trim());
      if (hexOnly && (inputWif.length === 64 || inputWif.length === 128)) {
        privKeyHex =
          inputWif.length === 128 ? inputWif.substring(0, 64) : inputWif;
      } else {
        try {
          const decode = Bitcoin.Base58.decode(inputWif);
          const keyWithVersion = decode.slice(0, decode.length - 4);
          let key = keyWithVersion.slice(1);
          if (key.length >= 33 && key[key.length - 1] === 0x01) {
            key = key.slice(0, key.length - 1);
            compressed = true;
          }
          privKeyHex = Crypto.util.bytesToHex(key);
        } catch (e) {
          console.warn("Invalid WIF, generating new key:", e);
          const newKey = generateNewID();
          const decode = Bitcoin.Base58.decode(newKey.privKey);
          const keyWithVersion = decode.slice(0, decode.length - 4);
          let key = keyWithVersion.slice(1);
          if (key.length >= 33 && key[key.length - 1] === 0x01)
            key = key.slice(0, key.length - 1);
          privKeyHex = Crypto.util.bytesToHex(key);
        }
      }
    } else {
      const newKey = generateNewID();
      const decode = Bitcoin.Base58.decode(newKey.privKey);
      const keyWithVersion = decode.slice(0, decode.length - 4);
      let key = keyWithVersion.slice(1);
      if (key.length >= 33 && key[key.length - 1] === 0x01)
        key = key.slice(0, key.length - 1);
      privKeyHex = Crypto.util.bytesToHex(key);
    }

    // --- Derive addresses for each chain ---
    const result = { BTC: {}, FLO: {}, FET: {} };

    // BTC
    bitjs.pub = versions.BTC.pub;
    bitjs.priv = versions.BTC.priv;
    const pubKeyBTC = bitjs.newPubkey(privKeyHex);
    result.BTC.address = coinjs.bech32Address(pubKeyBTC).address;
    result.BTC.privateKey = bitjs.privkey2wif(privKeyHex);

    // FLO
    bitjs.pub = versions.FLO.pub;
    bitjs.priv = versions.FLO.priv;
    const pubKeyFLO = bitjs.newPubkey(privKeyHex);
    result.FLO.address = bitjs.pubkey2address(pubKeyFLO);
    result.FLO.privateKey = bitjs.privkey2wif(privKeyHex);

    // FET
    try {
      // Fetch.ai (Cosmos) requires compressed public keys
      bitjs.compressed = true;
      const pubKeyHex = bitjs.newPubkey(privKeyHex);
      
      // Calculate HASH160: RIPEMD160(SHA256(pubKey))
      const pubKeyBytes = Crypto.util.hexToBytes(pubKeyHex);
      const sha256Hash = Crypto.SHA256(pubKeyBytes, { asBytes: true });
      const ripemd160Hash = ripemd160(sha256Hash, { asBytes: true });
      
      // Bech32 encode with "fetch" prefix
      const bech32Words = coinjs.bech32_convert(ripemd160Hash, 8, 5, true);
      const fetchAddress = coinjs.bech32_encode("fetch", bech32Words);

      result.FET.address = fetchAddress;
      result.FET.privateKey = privKeyHex; // Fetch uses raw hex private key
    } catch (error) {
      console.error("Error generating FET address:", error);
      console.error("Private key:", privKeyHex);
      result.FET.address = "Error generating address";
      result.FET.privateKey = privKeyHex;
    }

    // restore
    bitjs.pub = origBitjsPub;
    bitjs.priv = origBitjsPriv;
    bitjs.compressed = origBitjsCompressed;
    coinjs.compressed = origCoinJsCompressed;

    return result;
  };

  // --- Address Translation ---
  fetCrypto.translateAddress = function (inputAddress) {
    if (!inputAddress) return null;
    inputAddress = inputAddress.trim();
    let hash160Bytes = null;

    try {
      if (inputAddress.startsWith("fetch1")) {
        const decoded = coinjs.bech32_decode(inputAddress);
        if (decoded && decoded.hrp === "fetch") {
          hash160Bytes = coinjs.bech32_convert(decoded.data, 5, 8, false);
        }
      } else if (inputAddress.toLowerCase().startsWith("bc1q")) {
        const decoded = coinjs.bech32_decode(inputAddress);
        if (decoded && decoded.hrp === "bc") {
          const version = decoded.data.shift();
          const converted = coinjs.bech32_convert(decoded.data, 5, 8, false);
          // P2WPKH: version is 0, followed by 20 bytes hash
          if (version === 0 && converted && converted.length === 20) {
            hash160Bytes = converted;
          }
        }
      } else {
        // Assume Base58Check (FLO or legacy BTC)
        const decoded = Bitcoin.Base58.decode(inputAddress);
        // Base58Check: 1 byte version + 20 bytes hash160 + 4 bytes checksum
        if (decoded && decoded.length === 25) {
          hash160Bytes = decoded.slice(1, 21);
        }
      }
    } catch (e) {
      console.warn("Invalid address format:", e);
      return null;
    }

    if (!hash160Bytes || hash160Bytes.length !== 20) {
      return null;
    }

    const result = { BTC: {}, FLO: {}, FET: {} };

    // Generate FET address
    try {
      const bech32Words = coinjs.bech32_convert(hash160Bytes, 8, 5, true);
      result.FET.address = coinjs.bech32_encode("fetch", bech32Words);
    } catch (e) {
      result.FET.address = "Error";
    }

    // Generate FLO address (Base58, version 0x23 / 35)
    try {
      let bytes = [0x23].concat(hash160Bytes);
      const hash = Crypto.SHA256(Crypto.SHA256(bytes, { asBytes: true }), { asBytes: true });
      const checksum = hash.slice(0, 4);
      result.FLO.address = bitjs.Base58.encode(bytes.concat(checksum));
    } catch (e) {
      result.FLO.address = "Error";
    }

    // Generate BTC address (SegWit P2WPKH, hrp 'bc', version 0)
    try {
      const bech32Words = coinjs.bech32_convert(hash160Bytes, 8, 5, true);
      const versionAndData = [0].concat(bech32Words);
      result.BTC.address = coinjs.bech32_encode("bc", versionAndData);
    } catch (e) {
      result.BTC.address = "Error";
    }

    return result;
  };
})("object" === typeof module ? module.exports : (window.fetCrypto = {}));
