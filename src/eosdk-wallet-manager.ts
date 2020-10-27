import crypto from 'crypto'
import { Numeric } from 'eosjs'
import { PrivateKey } from 'eosjs/dist/eosjs-key-conversions'
import { Wallet, defaultEc } from './eosdk-wallet'
import { KvStore } from './kvstore'
import { WalletNotFoundError, WalletExistsError } from './eosdk-wallet-errors'

const passwordPrefix = 'PW'

class WalletManager {
  private wallets: Map<string, Wallet> = new Map<string, Wallet>()

  public static generatePassword(): string {
    const rawKey: Numeric.Key = {
      type: Numeric.KeyType.k1,
      data: crypto.randomBytes(32)
    }
    const privateKey = new PrivateKey(rawKey, defaultEc)
    return passwordPrefix + privateKey.toString()
  }

  constructor(private kvstore: KvStore = new KvStore()) {}

  public async createWallet(walletName: string, password?: string): Promise<string> {
    if (this.wallets.has(walletName)) {
      throw new WalletExistsError()
    }
    try {
      await this.kvstore.get(walletName)
    } catch (e) {
      if (!password) {
        password = WalletManager.generatePassword()
      }
      const wallet = Wallet.create(walletName, password, this.kvstore)
      this.wallets.set(walletName, wallet)
      return password
    }
    throw new WalletExistsError()
  }

  public createKey(walletName: string): string  {
    if (!this.wallets.has(walletName)) {
      throw new WalletNotFoundError()
    }
    const wallet = this.wallets.get(walletName) as Wallet
    const publicKey = wallet.createKey()
    return publicKey
  }

  public async saveWallet(walletName: string): Promise<void> {
    if (!this.wallets.has(walletName)) {
      throw new WalletNotFoundError()
    }
    const wallet = this.wallets.get(walletName) as Wallet
    await wallet.save()
  }

  public async loadWallet(walletName: string): Promise<void> {
    try {
      const encryptedWallet = await this.kvstore.get(walletName)
      const wallet = new Wallet(walletName, JSON.parse(encryptedWallet), this.kvstore)
      if (this.wallets.has(walletName)) {
        this.wallets.delete(walletName)
      }
      this.wallets.set(walletName, wallet)
    } catch (e) {
      throw new WalletNotFoundError()
    }
  }

  // For test, this will be removed in the future version
  public getWallet(walletName = 'default'): Wallet | undefined {
    return this.wallets.get(walletName)
  }
}

export { WalletManager }
