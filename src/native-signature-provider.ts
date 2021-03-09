import { Numeric, ApiInterfaces, RpcInterfaces } from 'eosjs'
import { digestFromSerializedData } from './eoscore-wallet-utils'
import { UnsupportedKeyTypeError }  from './eoscore-wallet-errors'
import { secp256k1 } from './crypto'

function isCanonicalSignature(sigData: Uint8Array): boolean {
  return !(sigData[0] & 0x80) && !(sigData[0] === 0 && !(sigData[1] & 0x80))
  && !(sigData[32] & 0x80) && !(sigData[32] === 0 && !(sigData[33] & 0x80))
}

class NativeSignatureProvider implements ApiInterfaces.SignatureProvider {
  public keys = new Map<string, Buffer>()
  public availableKeys = [] as string[]

  constructor(privateKeys: string[]) {
    for (const k of privateKeys) {
      const priv = Numeric.stringToPrivateKey(k)
      if (priv.type !== Numeric.KeyType.k1) {
        throw new UnsupportedKeyTypeError()
      }
      const pubStr = Numeric.publicKeyToString({ type: priv.type, data: secp256k1.publicKeyCreate(Buffer.from(priv.data)) })
      this.keys.set(pubStr, Buffer.from(priv.data))
      this.availableKeys.push(pubStr)
    }
  }

  public async getAvailableKeys(): Promise<string[]> {
    return this.availableKeys
  }

  private _sign(digest: Buffer, publicKey: Numeric.Key, privateKey: Buffer) {
    let rawSignature = {
      0: Buffer.alloc(64),
      1: 0
    }
    do {
      rawSignature = secp256k1.signRecoverable(digest, privateKey, rawSignature[0].slice(0, 32))
      rawSignature[0] = secp256k1.signatureNormalize(rawSignature[0])
    } while (!isCanonicalSignature(rawSignature[0]))
    return {
      type: publicKey.type,
      data: Buffer.concat([
        Buffer.from([rawSignature[1] + 27]),
        Buffer.from(rawSignature[0])
      ])
    }
  }

  public async sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    const { chainId, serializedTransaction, serializedContextFreeData, requiredKeys } = args
    const digest = digestFromSerializedData(chainId, serializedTransaction, serializedContextFreeData)
    const signatures = [] as string[]
    for (const key of requiredKeys) {
      const publicKey = Numeric.stringToPublicKey(key)
      const privateKey = this.keys.get(Numeric.convertLegacyPublicKey(key)) as Buffer
      const signature = this._sign(digest, publicKey, privateKey)
      signatures.push(Numeric.signatureToString(signature))
    }
    return { signatures, serializedTransaction, serializedContextFreeData }
  }

  public async trySignDigest(digest: Buffer, key: string): Promise<string | undefined> {
    const privateKey = this.keys.get(key)
    if (!privateKey) {
      return undefined
    }
    const publicKey = Numeric.stringToPublicKey(key)
    const signature = this._sign(digest, publicKey, privateKey)
    return Numeric.signatureToString(signature)
  }
}

export { NativeSignatureProvider }
