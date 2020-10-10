export interface WalletData {
  cipher_keys: string
}

export interface KvStoreBackend {
  set: (key: string, value: string) => void
  get: (key: string) => Promise<string>
  del: (key: string) => void
}
