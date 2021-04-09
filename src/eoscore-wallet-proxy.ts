import { ApiInterfaces, RpcInterfaces } from '@conr2d/eosjs'
import { Wallet } from './eoscore-wallet'
import { KeyNotFoundError } from './eoscore-wallet-errors'
import { digestFromSerializedData } from './eoscore-wallet-utils'

class WalletProxy implements ApiInterfaces.SignatureProvider {

  constructor(private wallets: Wallet[]) {}

  public async getAvailableKeys(): Promise<string[]> {
    const keys = [] as string[]
    for (const wallet of this.wallets) {
      if (!wallet.isLocked()) {
        keys.push(...(await wallet.getAvailableKeys()))
      }
    }
    return keys
  }

  public async sign(args: ApiInterfaces.SignatureProviderArgs): Promise<RpcInterfaces.PushTransactionArgs> {
    const { chainId, serializedTransaction, serializedContextFreeData, requiredKeys } = args
    const digest = digestFromSerializedData(chainId, serializedTransaction, serializedContextFreeData)
    const signatures = [] as string[]
    for (const key of requiredKeys) {
      let found = false
      for (const wallet of this.wallets) {
        const signature = await wallet.trySignDigest(digest, key)
        if (signature) {
          signatures.push(signature)
          found = true
          break
        }
      }
      if (!found) {
        throw new KeyNotFoundError()
      }
    }
    return { signatures, serializedTransaction, serializedContextFreeData }
  }
}

export { WalletProxy }
