import { KvStoreBackend } from './eosdk-wallet-interfaces'
import os from 'os'
import path from 'path'
import { constants, promises as fs } from 'fs'

class KvStoreFileSystemBackend implements KvStoreBackend {
  private dirpath: string
  private extension = '.wallet'

  constructor() {
    this.dirpath = path.join(os.homedir(), 'eosdk-wallet')
  }

  async set(key: string, value: string): Promise<void> {
    try {
      await fs.access(this.dirpath, constants.F_OK)
    } catch (e) {
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
      if (e.code === 'ENOENT') {
        await fs.mkdir(this.dirpath)
      } else throw e;
    }
    await fs.writeFile(path.join(this.dirpath, key + this.extension), value)
  }

  async get(key: string): Promise<string> {
    return await fs.readFile(path.join(this.dirpath, key + this.extension), 'utf8')
  }

  async del(key: string): Promise<void> {
    await fs.unlink(path.join(this.dirpath, key + this.extension))
  }
}

export { KvStoreFileSystemBackend }
