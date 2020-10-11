import { ApiInterfaces, RpcInterfaces, Numeric, Serialize } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { PublicKey, PrivateKey } from 'eosjs/dist/eosjs-key-conversions'
import hash from 'hash.js'
import { EncryptedWallet, DecryptedWallet } from './eosdk-wallet-interfaces'
import { WalletInvalidDataError, WalletInvalidPasswordError, WalletLockedError } from './eosdk-wallet-errors'
import { ec } from 'elliptic'
import { AES } from './crypto'
import crypto from 'crypto'

/* eslint-disable @typescript-eslint/no-var-requires */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
const walletAbi = require('../src/wallet.abi.json')

const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), walletAbi)

/** expensive to construct; so we do it once and reuse it */
const defaultEc = new ec('secp256k1') as any;

class Wallet implements ApiInterfaces.SignatureProvider {
  private jssig?: JsSignatureProvider
  private checksum?: Buffer

  public static create(password: string): Wallet {
    const checksum = Buffer.from(hash.sha512().update(password).digest())
    const buffer = new Serialize.SerialBuffer()
    buffer.pushUint8ArrayChecked(checksum, 64)
    buffer.pushVaruint32(0)
    const size = buffer.length
    const cipherKeys = AES.encrypt(checksum, buffer.asUint8Array()).slice(0, size+16);
    const wallet = new Wallet({
/* eslint-disable @typescript-eslint/naming-convention */
      cipher_keys: cipherKeys.toString('hex')
    })
    wallet.unlock(password)
    return wallet
  }

  constructor(private encrypted: EncryptedWallet) {}

  public unlock(password: string): void {
    try {
      this.checksum = Buffer.from(hash.sha512().update(password).digest())
      const decrypted = AES.decrypt(this.checksum, Buffer.from(this.encrypted.cipher_keys, 'hex'));
      const buffer = new Serialize.SerialBuffer({ array: decrypted })
      const wallet = types.get('wallet')
      const deser = wallet?.deserialize(buffer) as DecryptedWallet
      if (this.checksum.toString('hex').toLowerCase() !== deser.checksum.toLowerCase()) {
        throw new WalletInvalidPasswordError()
      }
      const keys = []
      for (const keyPair of deser.keys) {
        const priv = {
          type: PublicKey.fromString(keyPair.key).getType(),
          data: Buffer.from(keyPair.value.data, 'hex')
        }
        keys.push(new PrivateKey(priv, defaultEc).toString())
      }
      this.jssig = new JsSignatureProvider(keys)
    } catch (error) {
      this.checksum = undefined
      throw new WalletInvalidDataError()
    }
  }

  public lock(): void {
    this.serialize()
    this.checksum = undefined
    this.jssig = undefined
  }

  public getAvailableKeys(): Promise<string[]> {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    return this.jssig.getAvailableKeys()
  }

  public sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    return this.jssig.sign(args)
  }

  public serialize(): string {
    if (!this.jssig) {
      return JSON.stringify(this.encrypted)
    }
    const buffer = new Serialize.SerialBuffer()
    buffer.pushUint8ArrayChecked(this.checksum as Buffer, 64)
    buffer.pushVaruint32(this.jssig.keys.size)
    this.jssig.keys.forEach((priv: ec.KeyPair, pub: string) => {
      buffer.pushPublicKey(pub)
      const publicKey = PublicKey.fromString(pub)
      buffer.pushPrivateKey(PrivateKey.fromElliptic(priv, publicKey.getType(), defaultEc).toString())
    })
    const size = buffer.length
    const cipherKeys = AES.encrypt(this.checksum as Buffer, buffer.asUint8Array()).slice(0, size+16);
    this.encrypted = {
      cipher_keys: cipherKeys.toString('hex')
    }
    return JSON.stringify(this.encrypted)
  }

  public importKey(privateKey: string): string {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    const priv = PrivateKey.fromString(privateKey)
    const privElliptic = priv.toElliptic()
    const pubStr = priv.getPublicKey().toString()
    if (!this.jssig.keys.has(pubStr)) {
      this.jssig.keys.set(pubStr, privElliptic)
      this.jssig.availableKeys.push(pubStr)
    }
    return pubStr
  }

  public createKey(): string {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    const rawKey: Numeric.Key = {
      type: Numeric.KeyType.k1,
      data: crypto.randomBytes(32)
    }
    const privateKey = new PrivateKey(rawKey, defaultEc)
    return this.importKey(privateKey.toString())
  }
}

export { Wallet, defaultEc }
