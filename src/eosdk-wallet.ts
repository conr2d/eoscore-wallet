import { ApiInterfaces, RpcInterfaces, Serialize } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { PublicKey, PrivateKey } from 'eosjs/dist/eosjs-key-conversions'
import hash from 'hash.js'
import { WalletData } from './eosdk-wallet-interfaces'
import { WalletInvalidDataError, WalletInvalidPasswordError, WalletLockedError } from './eosdk-wallet-errors'
import { ec } from 'elliptic'
import { AES } from './crypto'

// tslint:disable:no-var-requires
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
      const decrypted = AES.decrypt(this.checksum, Buffer.from(this.walletData.cipher_keys, 'hex'));
      const buffer = new Serialize.SerialBuffer({ array: decrypted })
      const wallet = types.get('wallet')
      const deser = wallet?.deserialize(buffer)
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
      this.checksum = null
      throw new WalletInvalidDataError()
    }
  }

  public lock() {
    this.checksum = null
    this.jssig = null
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
    const encrypted = AES.encrypt(this.checksum, buffer.asUint8Array()).slice(0, size+16);
    return JSON.stringify({
      cipher_keys: encrypted.toString('hex')
    })
  }
}

export { Wallet }
