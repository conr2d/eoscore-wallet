import { hash } from './crypto'

export function digestFromSerializedData(
  chainId: string,
  serializedTransaction: Uint8Array,
  serializedContextFreeData?: Uint8Array,
) {
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
