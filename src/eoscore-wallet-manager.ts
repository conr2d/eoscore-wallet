import crypto from 'crypto'
import { Numeric, ApiInterfaces, RpcInterfaces } from 'eosjs'
import { Wallet } from './eoscore-wallet'
import { KvStore } from './kvstore'
import { WalletNotFoundError, WalletExistsError } from './eoscore-wallet-errors'
import { digestFromSerializedData } from './eoscore-wallet-utils'

const passwordPrefix = 'PW'

class WalletManager {
  private wallets: Map<string, Wallet> = new Map<string, Wallet>()

  public static generatePassword(): string {
    return passwordPrefix + Numeric.privateKeyToLegacyString({ type: Numeric.KeyType.k1, data: crypto.randomBytes(32) })
  }

  constructor(private kvstore: KvStore = new KvStore()) {}

  public async createWallet(walletName: string, password?: string): Promise<string> {
    if (this.wallets.has(walletName)) {
      throw new WalletExistsError()
    }
    if (await this.kvstore.get(walletName)) {
      throw new WalletExistsError()
    }
    if (!password) {
      password = WalletManager.generatePassword()
    }
    const wallet = Wallet.create(walletName, password, this.kvstore)
    this.wallets.set(walletName, wallet)
    return password
  }

  public createKey(walletName: string): string  {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new WalletNotFoundError()
    }
    const publicKey = wallet.createKey()
    return publicKey
  }

  public importKey(walletName: string, privateKey: string): string {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new WalletNotFoundError()
    }
    const publicKey = wallet.importKey(privateKey)
    return publicKey
  }

  public async saveWallet(walletName: string): Promise<void> {
    const wallet = this.wallets.get(walletName)
    if (!wallet) {
      throw new WalletNotFoundError()
    }
    await wallet.save()
  }

  public async loadWallet(walletName: string): Promise<void> {
    const encryptedWallet = await this.kvstore.get(walletName)
    if (!encryptedWallet) {
      throw new WalletNotFoundError()
    }
    const wallet = new Wallet(walletName, JSON.parse(encryptedWallet), this.kvstore)
    if (this.wallets.has(walletName)) {
      this.wallets.delete(walletName)
    }
    this.wallets.set(walletName, wallet)
  }

  public async getAvailableKeys(): Promise<string[]> {
    const keys = [] as string[]
    for (const wallet of this.wallets) {
      if (!wallet[1].isLocked()) {
        keys.push(...(await wallet[1].getAvailableKeys()))
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
        const signature = await wallet[1].trySignDigest(digest, key)
        if (signature) {
          signatures.push(signature)
          found = true
          break;
        }
      }
      if (!found) {
        throw new Error('required key is not found')
      }
    }
    return { signatures, serializedTransaction, serializedContextFreeData }
  }

  // For test, this will be removed in the future version
  public getWallet(walletName: string): Wallet | undefined {
    return this.wallets.get(walletName)
  }
}

export { WalletManager }
