import { KvStoreBackend } from './eoscore-wallet-interfaces'
import os from 'os'
import path from 'path'
import { constants, promises as fs } from 'fs'

class KvStoreFileSystemBackend implements KvStoreBackend {
  private dbpath: string
  private extension = '.wallet'

  constructor(dbpath?: string) {
    this.dbpath = dbpath ? dbpath : path.join(os.homedir(), 'eoscore-wallet')
  }

  async set(key: string, value: string): Promise<void> {
    try {
      await fs.access(this.dbpath, constants.F_OK)
    } catch (e) {
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
      if (e.code === 'ENOENT') {
        await fs.mkdir(this.dbpath)
      } else throw e;
    }
    await fs.writeFile(path.join(this.dbpath, key + this.extension), value)
  }

  async get(key: string): Promise<string> {
    return await fs.readFile(path.join(this.dbpath, key + this.extension), 'utf8')
  }

  async del(key: string): Promise<void> {
    await fs.unlink(path.join(this.dbpath, key + this.extension))
  }
}

export { KvStoreFileSystemBackend }
