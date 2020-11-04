import { KvStoreBackend } from './eoscore-wallet-interfaces'
import { KvStoreInMemoryBackend } from './kvstore-inmemory-backend'

class KvStore {
  constructor(private backend: KvStoreBackend = new KvStoreInMemoryBackend()) {}

  async set(key: string, value: string): Promise<void> {
    await this.backend.set(key, value)
  }

  async get(key: string): Promise<string | undefined> {
    return await this.backend.get(key)
  }

  async del(key: string): Promise<void> {
    await this.backend.del(key)
  }
}

export { KvStore }
