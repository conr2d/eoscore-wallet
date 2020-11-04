import secp256k1 from 'secp256k1'
import { Numeric, ApiInterfaces, RpcInterfaces } from 'eosjs'
import { hash } from './crypto'

const digestFromSerializedData = (
  chainId: string,
  serializedTransaction: Uint8Array,
  serializedContextFreeData?: Uint8Array,
) => {
  const signBuf = Buffer.concat([
    Buffer.from(chainId, 'hex'),
    Buffer.from(serializedTransaction),
    Buffer.from(
      serializedContextFreeData ?
      new Uint8Array(hash.sha256().update(serializedContextFreeData).digest()) :
      new Uint8Array(32)
    ),
  ])
  return hash.sha256().update(signBuf).digest()
}

class NativeSignatureProvider implements ApiInterfaces.SignatureProvider {
  public keys = new Map<string, Buffer>()

  public availableKeys = [] as string[]

  constructor(privateKeys: string[]) {
    for (const k of privateKeys) {
      const priv = Numeric.stringToPrivateKey(k)
      if (priv.type !== Numeric.KeyType.k1) {
        throw new Error('not supported key type')
      }
      const pubStr = Numeric.publicKeyToString({ type: priv.type, data: secp256k1.publicKeyCreate(priv.data) })
      this.keys.set(pubStr, Buffer.from(priv.data))
      this.availableKeys.push(pubStr)
    }
  }

  public async getAvailableKeys(): Promise<string[]> {
    return this.availableKeys
  }

  public async sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    const { chainId, serializedTransaction, serializedContextFreeData, requiredKeys } = args
    const digest = digestFromSerializedData(chainId, serializedTransaction, serializedContextFreeData)

    const signatures = [] as string[];
    for (const key of requiredKeys) {
      const publicKey = Numeric.stringToPublicKey(key)
      const privateKey = this.keys.get(Numeric.convertLegacyPublicKey(key)) as Buffer
      const rawSignature = secp256k1.ecdsaSign(digest, privateKey)
      const signature = {
        type: publicKey.type,
        data: Buffer.concat([
          Buffer.from([rawSignature.recid + 27]),
          Buffer.from(rawSignature.signature)
        ])
      }
      signatures.push(Numeric.signatureToString(signature))
    }

    return { signatures, serializedTransaction, serializedContextFreeData }
  }
}

export { NativeSignatureProvider }
