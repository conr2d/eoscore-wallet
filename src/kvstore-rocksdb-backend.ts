import { KvStoreBackend } from './eosdk-wallet-interfaces'
import os from 'os'
import path from 'path'

const level = require('level-rocksdb')

class KvStoreRocksDBBackend implements KvStoreBackend {
  private db
  private dbpath: string

  constructor() {
    this.dbpath = path.join(os.homedir(), 'eosdk-wallet')
    this.db = level(this.dbpath)
  }

  async set(key: string, value: string) {
    await this.db.put(key, value)
  }

  async get(key: string): Promise<string> {
    return await this.db.get(key)
  }

  async del(key: string) {
    await this.db.del(key)
  }
}

export { KvStoreRocksDBBackend }
