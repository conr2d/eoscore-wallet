import { PrivateKey } from '@conr2d/eosjs/dist/eosjs-key-conversions'
import { JsSignatureProvider as EosJsSignatureProvider } from '@conr2d/eosjs/dist/eosjs-jssig'

class JsSignatureProvider extends EosJsSignatureProvider {

  public async trySignDigest(digest: Buffer, key: string): Promise<string | undefined> {
    const priv = this.keys.get(key)
    if (!priv) {
      return undefined
    }
    const privateKey = new PrivateKey(priv)
    const signature = privateKey.sign(digest, false)
    return signature.toString()
  }
}

export { JsSignatureProvider }
