import { KvStoreBackend } from './eoscore-wallet-interfaces'
import { KvStoreInMemoryBackend } from './kvstore-inmemory-backend'

class KvStore {
  constructor(private backend: KvStoreBackend = new KvStoreInMemoryBackend()) {}

  set(key: string, value: string): Promise<void> {
    return this.backend.set(key, value)
  }

  get(key: string): Promise<string | undefined> {
    return this.backend.get(key)
  }

  del(key: string): Promise<void> {
    return this.backend.del(key)
  }
}

export { KvStore }
