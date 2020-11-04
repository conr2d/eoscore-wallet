/* eslint-disable max-classes-per-file */
export class WalletInvalidDataError extends Error {
  constructor() {
    super('wallet data is invalid')
    Object.setPrototypeOf(this, WalletInvalidDataError.prototype)
  }
}

export class WalletInvalidPasswordError extends Error {
  constructor() {
    super('wallet password is invalid')
    Object.setPrototypeOf(this, WalletInvalidPasswordError.prototype)
  }
}

export class WalletLockedError extends Error {
  constructor() {
    super('wallet is locked')
    Object.setPrototypeOf(this, WalletLockedError.prototype)
  }
}

export class WalletNotFoundError extends Error {
  constructor() {
    super('wallet is not found')
    Object.setPrototypeOf(this, WalletNotFoundError.prototype)
  }
}

export class WalletExistsError extends Error {
  constructor() {
    super('wallet exists already')
    Object.setPrototypeOf(this, WalletExistsError.prototype)
  }
}

export class KeyNotFoundError extends Error {
  constructor() {
    super('key is not found')
    Object.setPrototypeOf(this, KeyNotFoundError.prototype)
  }
}

export class UnsupportedKeyTypeError extends Error {
  constructor() {
    super('key type is not supported')
    Object.setPrototypeOf(this, UnsupportedKeyTypeError.prototype)
  }
}
