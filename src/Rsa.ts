import bigInt from "big-integer"
import {BigInt, RsaMembers} from "./types";


/**
 * TypeScript implementation
 */
export default class Rsa {
  /**
   * Generates a random k-bit prime greater than sqrt(2) × 2^(k-1)
   *
   * @param   bits number of
   * @returns {bigInt} a random generated prime
   */
  private static randomPrime(bits: number) {
    const min = bigInt(6074001000).shiftLeft(bits - 33);
    const max = bigInt.one.shiftLeft(bits).minus(1);
    for (; ;) {
      const p = bigInt.randBetween(min, max);
      if (p.isProbablePrime(256)) {
        return p;
      }
    }
  }

  /**
   * Generates a k-bit RSA public/private key pair
   *
   * @param size Bitlength of desired RSA modulus n (should be even)
   * @param e Public exponent
   */
  static generateKey(size: number, e: BigInt = bigInt(65537)): RsaMembers {
    let p;
    let q;
    let lambda;

    do {
      p = this.randomPrime(size / 2);
      q = this.randomPrime(size / 2);
      lambda = bigInt.lcm(p.minus(1), q.minus(1));
    } while (bigInt.gcd(e, lambda).notEquals(1) || p.minus(q).abs().shiftRight(size / 2 - 100).isZero());

    console.log(p, q);

    return {
      n: p.multiply(q),
      e: e,
      d: e.modInv(lambda),
    }
  }

  /**
   * Encrypt
   *
   * @param m The 'message' to be encoded
   * @param n n value returned from RSA.generate() aka public key (part I)
   * @param e e value returned from RSA.generate() aka public key (part II)
   * @returns Encrypted message
   */
  static encrypt(m: BigInt, n: BigInt, e: BigInt): BigInt {
    return bigInt(m).modPow(e, n);
  }

  /**
   * Decrypt
   *
   * @param   c the 'message' to be decoded (encoded with RSA.encrypt())
   * @param   d d value returned from RSA.generate() aka private key
   * @param   n n value returned from RSA.generate() aka public key (part I)
   * @returns Decrypted message
   */
  static decrypt(c: BigInt, d: BigInt, n: BigInt): BigInt {
    return bigInt(c).modPow(d, n);
  }
}