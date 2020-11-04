import { Numeric } from 'eosjs'

/* eslint-disable @typescript-eslint/naming-convention */
export interface EncryptedWallet {
  cipher_keys: string
}

interface KeyPair {
  key: string
  value: Key
}

interface Key {
  type: Numeric.KeyType
  data: string
}

export interface DecryptedWallet {
  checksum: string
  keys: KeyPair[]
}

export interface KvStoreBackend {
  set: (key: string, value: string) => Promise<void>
  get: (key: string) => Promise<string>
  del: (key: string) => Promise<void>
}
