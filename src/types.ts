import bigInt from "big-integer";

export type BigInt = bigInt.BigInteger;

export interface RsaMembers {
  d: BigInt,
  e: BigInt,
  n: BigInt
}
