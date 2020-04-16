import {BigInt} from "./types";
import bigInt from "big-integer";
import Rsa from "./Rsa";

export default class Cracker {
  private static fermatFactors(n: number) {
    let a = Math.ceil(Math.sqrt(n));
    let b2 = a ** 2 - n;
    while (Math.ceil(Math.sqrt(b2)) ** 2 !== b2) {
      b2 += 2 * a + 1;
      a++;
    }

    const b = Math.sqrt(b2);
    return [a - b, a + b];
  }

  static crackPrivateKey(n: BigInt, e: BigInt): BigInt {
    const [p, q] = this.fermatFactors(n.valueOf());
    const lambda = bigInt.lcm(bigInt(p).minus(1), bigInt(q).minus(1));

    return e.modInv(lambda);
  }

  static cycleCrack(c: BigInt, n: BigInt, e: BigInt, cycles?: number): BigInt {
    const _cycles = cycles ?? this.cycleAttack(n, e);
    let result = c;

    for (let i = 0; i < _cycles; i++) {
      result = Rsa.encrypt(result, n, e);
    }

    return result;
  }

  static cycleAttack(n: BigInt, e: BigInt): number {
    const msg = bigInt(1234);
    let result = msg;
    let count = 0;

    while ((result = Rsa.encrypt(result, n, e)).notEquals(msg)) {
      count++;
    }

    return count;
  }
}