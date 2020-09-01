import { ApiInterfaces, RpcInterfaces, Serialize } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { PublicKey, PrivateKey } from 'eosjs/dist/eosjs-key-conversions'
import hash from 'hash.js'
import aes from 'aes-js'
import { WalletData } from './eosdk-wallet-interfaces'
import { WalletInvalidDataError, WalletInvalidPasswordError, WalletLockedError } from './eosdk-wallet-errors'
import { ec } from 'elliptic'

// tslint:disable:no-var-requires
const bs58check = require('bs58check')
const walletAbi = require('../src/wallet.abi.json')

const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), walletAbi)

/** expensive to construct; so we do it once and reuse it */
const defaultEc = new ec('secp256k1') as any;

class Wallet implements ApiInterfaces.SignatureProvider {
  private jssig: any
  private checksum: any

  constructor(private walletData: WalletData) {}

  public async unlock(password: string): Promise<void> {
    try {
      this.checksum = Buffer.from(hash.sha512().update(password).digest())
      const key = this.checksum.slice(0, 32)
      const iv = this.checksum.slice(32, 48)
      const cbc = new aes.ModeOfOperation.cbc(key, iv)
      const decrypted = aes.padding.pkcs7.strip(cbc.decrypt(Buffer.from(this.walletData.cipher_keys, 'hex')))
      const buffer = new Serialize.SerialBuffer({ array: decrypted })
      const wallet = types.get('wallet')
      const deser = wallet?.deserialize(buffer)
      if (this.checksum.toString('hex').toLowerCase() !== deser.checksum.toLowerCase()) {
        throw new WalletInvalidPasswordError()
      }
      const keys = []
      for (const keyPair of deser.keys) {
        const prefix = Buffer.from('80', 'hex')
        const priv = Buffer.from(keyPair.value.data, 'hex')
        keys.push(bs58check.encode(Buffer.concat([prefix, priv])))
      }
      this.jssig = new JsSignatureProvider(keys)
    } catch (error) {
      delete this.checksum
      throw new WalletInvalidDataError()
    }
  }

  public lock() {
    delete this.checksum
    delete this.jssig
  }

  public async getAvailableKeys(): Promise<string[]> {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    return this.jssig.getAvailableKeys()
  }

  public async sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    if (!this.jssig) {
      throw new WalletLockedError()
    }
    return this.jssig.sign(args)
  }

  public async serialize(): Promise<string> {
    if (!this.jssig) {
      return JSON.stringify(this.walletData)
    }
    const buffer = new Serialize.SerialBuffer()
    buffer.pushUint8ArrayChecked(this.checksum, 64)
    buffer.pushVaruint32(this.jssig.keys.size)
    this.jssig.keys.forEach((priv: ec.KeyPair, pub: string) => {
      buffer.pushPublicKey(pub)
      const publicKey = PublicKey.fromString(pub)
      buffer.pushPrivateKey(PrivateKey.fromElliptic(priv, publicKey.getType(), defaultEc).toString())
    })
    const size = buffer.length
    const key = this.checksum.slice(0, 32)
    const iv = this.checksum.slice(32, 48)
    const cbc = new aes.ModeOfOperation.cbc(key, iv)
    const encrypted = Buffer.from(cbc.encrypt(aes.padding.pkcs7.pad(buffer.asUint8Array()))).slice(0, size+16)
    return JSON.stringify({
      cipher_keys: encrypted.toString('hex')
    })
  }
}

export { Wallet }
