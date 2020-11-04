import { KvStoreBackend } from './eoscore-wallet-interfaces'

class KvStoreInMemoryBackend implements KvStoreBackend {
  private db = new Map<string,string>()

  async set(key: string, value: string): Promise<void> {
    await this.db.set(key, value)
  }

  async get(key: string): Promise<string | undefined> {
    return await this.db.get(key)
  }

  async del(key: string): Promise<void> {
    await this.db.delete(key)
  }
}

export { KvStoreInMemoryBackend }
