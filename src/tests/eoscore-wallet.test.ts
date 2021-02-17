import { Wallet } from '../eoscore-wallet'
import { EncryptedWallet } from '../eoscore-wallet-interfaces'
import { Numeric } from 'eosjs'
import { secp256k1 } from '../crypto'

const encryptedWallet = `
{
  "cipher_keys": "2aaf75a42e5de2e07bfaac2e174def0c0243bb5b9e0b948fda2c2acb72a03256dd646e3eb16982422b430ffcc9782a5bbe5d640feb14388d9ed1c6d159e54c761e8a4af4f23754425d736e6cdf834f2339ca41cbf997bde4aa483ea2ae6083190b18030ca6881e38ae7bd47478cae0529ab1ab26136e920938ae1a666eef4686423c6b5b3e0b90ab37e882e8508852e3b09c1c2da488f6840b35766d7d9e71336fec7d3c5a7e62545805e85f907f20579d971f90b7e2a77c031a23715caa757118b0afc124bfdf3b4c8f046616df5914"
}`
const password = 'PW5KZWKXfKJmUGN76MTLbnTfRZDf8s3bLr71jEHHaTMd6bXw2tX31'

describe('eoscore-wallet', () => {
  let wallet: Wallet

  beforeEach(() => {
    wallet = new Wallet('default', JSON.parse(encryptedWallet))
  })

  it('unlock decrypts cipher_keys in wallet data', async () => {
    wallet.unlock(password)
    const decryptedKeys: string[] = await wallet.getAvailableKeys()

    const keys = [
      'PUB_K1_4urxYs1SjvNyqN17ZNyg1WhWNtwW3SQz9ArXn4oGbQ6mwC6qBT',
      'PUB_K1_7bFuFaYy5kYmcgBaNz8KTdmWBnjYHYvEP1YwkHxfA4uLVp4F8B'
    ]

    const compareKeys = decryptedKeys.length === keys.length && decryptedKeys.every((value, _) => {
      return keys.indexOf(value) >= 0
    })

    expect(compareKeys).toEqual(true)
  })

  it('serialize encrypts wallet data', () => {
    wallet.unlock(password)
    const serializedWallet = wallet.serialize()
    const cipherKeys = (JSON.parse(encryptedWallet) as EncryptedWallet).cipher_keys
    const serializedCipherKeys = (JSON.parse(serializedWallet) as EncryptedWallet).cipher_keys

    expect(cipherKeys === serializedCipherKeys).toEqual(true)
  })

  it('trySignDigest generates a valid signature', async () => {
    wallet.unlock(password)
    const digest = Buffer.alloc(32)
    const publicKey = 'PUB_K1_4urxYs1SjvNyqN17ZNyg1WhWNtwW3SQz9ArXn4oGbQ6mwC6qBT'
    const signatureStr = (await wallet.trySignDigest(digest, publicKey)) as string
    const signature = Numeric.stringToSignature(signatureStr)
    const recoveredKey = {
      type: Numeric.KeyType.k1,
      data: secp256k1.recover(digest, Buffer.from(signature.data.slice(1)), signature.data[0] - 27),
    }

    expect(Numeric.publicKeyToString(recoveredKey)).toEqual(publicKey)
  })
})
