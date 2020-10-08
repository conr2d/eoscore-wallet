import aes from 'aes-js'

class AES {
  public static encrypt(key: Buffer | Uint8Array, plainText: Buffer | Uint8Array): Buffer {
    const cbc = new aes.ModeOfOperation.cbc(key.slice(0, 32), key.slice(32, 48))
    return Buffer.from(cbc.encrypt(aes.padding.pkcs7.pad(plainText)))
  }

  public static decrypt(key: Buffer | Uint8Array, cipherText: Buffer | Uint8Array): Buffer {
    const cbc = new aes.ModeOfOperation.cbc(key.slice(0, 32), key.slice(32, 48))
    return Buffer.from(aes.padding.pkcs7.strip(cbc.decrypt(cipherText)))
  }
}

export { AES }
