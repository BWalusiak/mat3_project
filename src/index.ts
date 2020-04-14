import Rsa from "./Rsa"
import bigInt from "big-integer";
import Cracker from "./Cracker";

const {d, e, n} = Rsa.generateKey(32);
console.log(`RSA numbers:`, {d, e, n});

const message = bigInt(123456789);
console.log(`Message: ${message}`);

const encrypted = Rsa.encrypt(message, n, e);
console.log(`Encrypted message: ${encrypted}`);

const decrypted = Rsa.decrypt(encrypted, d, n);
console.log(`Decrypted message ${decrypted}`);

const crackedPrivateKey = Cracker.crackPrivateKey(n, e);
console.log(`Private d: ${d}, cracked: ${crackedPrivateKey}`);

const cycles = Cracker.cycleAttack(n, e);
console.log(`Cycle attack: ${cycles}`);

const crackedWithCycles = Cracker.cycleCrack(encrypted, n, e, cycles);
console.log(`Cracked message: ${crackedWithCycles}`);
