import { KvStoreRocksDBBackend } from './kvstore-rocksdb-backend'

class KvStore {
  constructor(private backend: KvStoreRocksDBBackend = new KvStoreRocksDBBackend()) {}

  async set(key: string, value: string): Promise<void> {
    await this.backend.set(key, value)
  }

  async get(key: string): Promise<string> {
    return await this.backend.get(key)
  }

  async del(key: string): Promise<void> {
    await this.backend.del(key)
  }
}

export { KvStore }
