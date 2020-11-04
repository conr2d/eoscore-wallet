import { KvStoreBackend } from './eoscore-wallet-interfaces'
import os from 'os'
import path from 'path'

/* eslint-disable @typescript-eslint/no-var-requires */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
const level = require('level-rocksdb')

class KvStoreRocksDBBackend implements KvStoreBackend {
  private db
  private dbpath: string

  constructor(dbpath?: string) {
    this.dbpath = dbpath ? dbpath : path.join(os.homedir(), 'eoscore-wallet')
    this.db = level(this.dbpath)
  }

  async set(key: string, value: string): Promise<void> {
    await this.db.put(key, value)
  }

  async get(key: string): Promise<string> {
    return (await this.db.get(key)) as string
  }

  async del(key: string): Promise<void> {
    await this.db.del(key)
  }
}

export { KvStoreRocksDBBackend }
