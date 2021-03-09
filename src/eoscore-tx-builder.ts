// This is adapted from 'develop' branch of eosjs. (Brad Hart)
import { Api, Serialize, ApiInterfaces, RpcInterfaces } from 'eosjs'
import { WalletManager } from './eoscore-wallet-manager'

interface ActionSerializerType {
  [actionName: string]: any
}

class TransactionBuilder {
  public actions: Serialize.SerializedAction[] = []

  constructor(private api: Api, private walletManager?: WalletManager) {}

  public Contract(accountName: string): ActionBuilder {
    const actionBuilder = new ActionBuilder(this, this.api, accountName)
    return actionBuilder
  }

  private async tryGetBlockHeaderState(taposBlockNumber: number): Promise<any> {
    try {
      return await this.api.rpc.get_block_header_state(taposBlockNumber)
    } catch (error) {
      return await this.api.rpc.get_block(taposBlockNumber)
    }
  }

  public async send({
    broadcast = true, sign = true, compression, blocksBehind = 3, useLastIrreversible, expireSeconds = 30 }:
    ApiInterfaces.TransactConfig = {}): Promise<any>
  {
    if (typeof blocksBehind === 'number' && useLastIrreversible) {
      throw new Error('Use either blocksBehind or useLastIrreversible')
    }
    let info: RpcInterfaces.GetInfoResult = await this.api.rpc.get_info()
    if (!this.api.chainId) {
      this.api.chainId = info.chain_id
    }
    const taposBlockNumber: number = useLastIrreversible
      ? info.last_irreversible_block_num : info.head_block_num - blocksBehind
    const refBlock = taposBlockNumber <= info.last_irreversible_block_num
      ? await this.api.rpc.get_block(taposBlockNumber)
      : await this.tryGetBlockHeaderState(taposBlockNumber)
    let transaction = {
      ...Serialize.transactionHeader(refBlock, expireSeconds),
      actions: this.actions,
      // context_free_actions not supported yet
    }
    const serializedTransaction = this.api.serializeTransaction(transaction)
    let pushTransactionArgs: RpcInterfaces.PushTransactionArgs = {
      serializedTransaction, serializedContextFreeData: undefined, signatures: []
    }
    if (sign) {
      let wallets: string[] = []
      this.actions.forEach((action) => {
        action.authorization.forEach((authorization) => {
          wallets.push(authorization.actor)
        })
      })
      const wallet = this.walletManager ? this.walletManager.getProxy(wallets) : this.api.signatureProvider
      const availableKeys = await wallet.getAvailableKeys()
      const requiredKeys = await this.api.authorityProvider.getRequiredKeys({ transaction, availableKeys })
      pushTransactionArgs = await wallet.sign({
        chainId: this.api.chainId,
        requiredKeys,
        serializedTransaction,
        serializedContextFreeData: undefined,
        abis: [],
      })
    }
    if (broadcast) {
      if (compression) {
        const compressedSerializedTransaction = this.api.deflateSerializedArray(serializedTransaction)
        return this.api.rpc.send_transaction({
          signatures: pushTransactionArgs.signatures,
          compression: 1,
          serializedTransaction: compressedSerializedTransaction,
          serializedContextFreeData: this.api.deflateSerializedArray(new Uint8Array(0)),
        })
      } else {
        return this.api.rpc.send_transaction(pushTransactionArgs)
      }
    }
    return pushTransactionArgs as RpcInterfaces.PushTransactionArgs
  }
}

class ActionBuilder {
  constructor(private transactionBuilder: TransactionBuilder, private api: Api, private readonly accountName: string) {}

  public signedBy(actorName: string | Serialize.Authorization[] = []): ActionSerializerType {
    let authorization: Serialize.Authorization[] = []
    if (actorName && typeof actorName === 'string') {
      authorization = [{ actor: actorName, permission: 'active' }]
    } else {
      authorization = actorName as Serialize.Authorization[]
    }
    return new ActionSerializer(this.transactionBuilder, this.api, this.accountName, authorization) as ActionSerializerType
  }
}

class ActionSerializer implements ActionSerializerType {
  constructor(parent: TransactionBuilder, api: Api, accountName: string, authorization: Serialize.Authorization[]) {
    const jsonAbi = api.cachedAbis.get(accountName)
    if (!jsonAbi) {
      throw new Error('ABI must be cached before using ActionBuilder, run api.getAbi()')
    }
    const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), jsonAbi.abi)
    const actions = new Map<string, Serialize.Type>()
    for (const { name, type } of jsonAbi.abi.actions) {
      actions.set(name, Serialize.getType(types, type))
    }
    actions.forEach((type, name) => {
      Object.assign(this, {
        [name]: (...args: any[]) => {
          const data: { [key: string]: any } = {}
          args.forEach((arg, index) => {
            const field = type.fields[index]
            data[field.name] = arg
          })
          const serializedData = Serialize.serializeAction(
            { types, actions },
            accountName,
            name,
            authorization,
            data,
            api.textEncoder,
            api.textDecoder,
          )
          parent.actions.push(serializedData)
          return serializedData
        }
      })
    })
  }
}

export {
  TransactionBuilder,
}
