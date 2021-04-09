import { Numeric, Serialize, ApiInterfaces, RpcInterfaces } from '@conr2d/eosjs'
import { JsSignatureProvider } from './eoscore-jssig'
import { EncryptedWallet, DecryptedWallet } from './eoscore-wallet-interfaces'
import { WalletInvalidDataError, WalletInvalidPasswordError, WalletLockedError } from './eoscore-wallet-errors'
import { aes, hash, secp256k1 } from './crypto'
import crypto from 'crypto'
import { KvStore } from './kvstore'

/* eslint-disable @typescript-eslint/no-var-requires */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
const walletAbi = require('../src/wallet.abi.json')

const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), walletAbi)

class Wallet implements ApiInterfaces.SignatureProvider {
  private sig?: JsSignatureProvider
  private checksum?: Buffer

  public static create(name: string, password: string, kvstore: KvStore = new KvStore()): Wallet {
    const checksum = Buffer.from(hash.sha512().update(Buffer.from(password)).final())
    const buffer = new Serialize.SerialBuffer()
    buffer.pushUint8ArrayChecked(checksum, 64)
    buffer.pushVaruint32(0)
    const size = buffer.length
    const cipherKeys = aes.encrypt(checksum, buffer.asUint8Array()).slice(0, size+16)
    const wallet = new Wallet(name, {
/* eslint-disable @typescript-eslint/naming-convention */
      cipher_keys: cipherKeys.toString('hex')
    }, kvstore)
    wallet.unlock(password)
    return wallet
  }

  constructor(public readonly name: string, private encrypted: EncryptedWallet, private kvstore: KvStore = new KvStore()) {}

  public isLocked(): boolean {
    return !this.sig
  }

  public unlock(password: string): void {
    try {
      this.checksum = Buffer.from(hash.sha512().update(Buffer.from(password)).final())
      const decrypted = aes.decrypt(this.checksum, Buffer.from(this.encrypted.cipher_keys, 'hex'))
      const buffer = new Serialize.SerialBuffer({ array: decrypted })
      const wallet = types.get('wallet')
      const deser = wallet?.deserialize(buffer) as DecryptedWallet
      if (this.checksum.toString('hex').toLowerCase() !== deser.checksum.toLowerCase()) {
        throw new WalletInvalidPasswordError()
      }
      const keys = [] as string[]
      for (const keyPair of deser.keys) {
        keys.push(keyPair.value)
      }
      this.sig = new JsSignatureProvider(keys)
    } catch (error) {
      this.checksum = undefined
      throw new WalletInvalidDataError()
    }
  }

  public lock(): void {
    this.serialize()
    this.checksum = undefined
    this.sig = undefined
  }

  public getAvailableKeys(): Promise<string[]> {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    return this.sig.getAvailableKeys()
  }

  public sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    return this.sig.sign(args)
  }

  public trySignDigest(digest: Buffer, key: string): Promise<string | undefined> {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    return this.sig.trySignDigest(digest, key)
  }

  public serialize(): string {
    if (!this.sig) {
      return JSON.stringify(this.encrypted)
    }
    const buffer = new Serialize.SerialBuffer()
    buffer.pushUint8ArrayChecked(this.checksum as Buffer, 64)
    buffer.pushVaruint32(this.sig.keys.size)
    this.sig.keys.forEach((priv: Numeric.Key, pub: string) => {
      buffer.pushPublicKey(pub)
      buffer.pushPrivateKey(Numeric.privateKeyToString(priv))
    })
    const size = buffer.length
    const cipherKeys = aes.encrypt(this.checksum as Buffer, buffer.asUint8Array()).slice(0, size+16)
    this.encrypted = {
      cipher_keys: cipherKeys.toString('hex')
    }
    return JSON.stringify(this.encrypted, undefined, 2)
  }

  public importKey(privateKey: string): string {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    const priv = Numeric.stringToPrivateKey(privateKey)
    const pubStr = Numeric.publicKeyToString({ type: priv.type, data: Buffer.from(secp256k1.publicKeyCreate(Buffer.from(priv.data))) })
    if (!this.sig.keys.has(pubStr)) {
      this.sig.keys.set(pubStr, priv)
      this.sig.availableKeys.push(pubStr)
      this.serialize()
    }
    return pubStr
  }

  public createKey(): string {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    return this.importKey(Numeric.privateKeyToString({ type: Numeric.KeyType.k1, data: crypto.randomBytes(32) }))
  }

  public async save(): Promise<void> {
    await this.kvstore.set(this.name, this.serialize())
  }

  public getPublicKeys(): string[] {
    if (!this.sig) {
      throw new WalletLockedError()
    }
    return Array.from(this.sig.keys.keys())
  }
}

export { Wallet }
