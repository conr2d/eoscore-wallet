import crypto from 'crypto'

class aes {
  public static encrypt(key: Buffer | Uint8Array, plainText: Buffer | Uint8Array): Buffer {
    const cipher = crypto.createCipheriv('aes-256-cbc', key.slice(0, 32), key.slice(32, 48))
    return Buffer.concat([cipher.update(plainText), cipher.final()])
  }

  public static decrypt(key: Buffer | Uint8Array, cipherText: Buffer | Uint8Array): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key.slice(0, 32), key.slice(32, 48))
    return Buffer.concat([decipher.update(cipherText), decipher.final()])
  }
}

class hash {
  public static sha256() {
    return crypto.createHash('sha256')
  }

  public static sha512() {
    return crypto.createHash('sha512')
  }
}

export {
  aes,
  hash
}
