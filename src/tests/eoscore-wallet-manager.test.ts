import { WalletManager } from '../eoscore-wallet-manager'
import { Wallet } from '../eoscore-wallet'
import { EncryptedWallet } from '../eoscore-wallet-interfaces'

const encryptedWallet = `
{
  "cipher_keys": "baaa2626f4cafa52608459103d8c16c246b7f42d500dc59fef9ccb2e0f48a9db95297070cefedca5afad038f46150d2c7850fed19db9d44c6e262d69bba646bf9f513f578ab8f71ff8ec9ddac76d23e7"
}`
const password = 'PW5JwFRT1hqfeJpV5d76jz3aGHsWxECbADJdzDX5nZpFm4ChmAA5b'
const walletName = 'default'

describe('eoscore-wallet-manager', () => {
  let walletManager: WalletManager

  beforeEach(() => {
    walletManager = new WalletManager()
  })

  it('createWallet creates wallet', async () => {
    await walletManager.createWallet(walletName, password)
    const wallet = walletManager.getWallet(walletName) as Wallet
    const serializedWallet = wallet.serialize()
    const cipherKeys = (JSON.parse(encryptedWallet) as EncryptedWallet).cipher_keys
    const serializedCipherKeys = (JSON.parse(serializedWallet) as EncryptedWallet).cipher_keys

    expect(cipherKeys === serializedCipherKeys).toEqual(true)
  })
})
