const _aes = require('@conr2d/bcrypto/lib/aes')
const random = require('@conr2d/bcrypto/lib/random')
const sha256 = require('@conr2d/bcrypto/lib/sha256')
const sha512 = require('@conr2d/bcrypto/lib/sha512')
const secp256k1 = require('@conr2d/bcrypto/lib/secp256k1')

class aes {
  public static encrypt(key: Buffer | Uint8Array, plainText: Buffer | Uint8Array): Buffer {
    return _aes.encipher(Buffer.from(plainText), Buffer.from(key.slice(0, 32)), Buffer.from(key.slice(32, 48)))
  }

  public static decrypt(key: Buffer | Uint8Array, cipherText: Buffer | Uint8Array): Buffer {
    return _aes.decipher(Buffer.from(cipherText), Buffer.from(key.slice(0, 32)), Buffer.from(key.slice(32, 48)))
  }
}

class hash {
  public static sha256() {
    const hasher = sha256.hash()
    hasher.init()
    return hasher
  }

  public static sha512() {
    const hasher = sha512.hash()
    hasher.init()
    return hasher
  }
}

function randomBytes(size: number) {
  return random.randomBytes(size)
}

export {
  aes,
  hash,
  randomBytes,
  secp256k1,
}
