'use strict'

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
  encryptWithElGamal // async, assumed to be added for government encryption
} = require('./lib')

const HMACCONST = "Crypto is cool";
const HKDFCONST = "Sam and James";

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {}; // keypair from generateCertificate
  }

  async generateSharedDHKey(name) {
    const receiverPubKey = this.certs[name].publicKey;
    return await computeDH(this.EGKeyPair.sec, receiverPubKey);
  }

  async generateChainingKey(name, sharedDHOutput) {
    if (this.conns[name] && this.conns[name].chainingKey) {
      return this.conns[name].chainingKey;
    } else {
      return sharedDHOutput;
    }
  }

  async generateCertificate(username) {
        
      const keypairObject = await generateEG();
    
      this.EGKeyPair = keypairObject;
      const myPublicKey = keypairObject.pub;
    
      const certificate = {
        username: username,
        publicKey: myPublicKey
      };
    
      this.certs[username] = certificate;
    
      return certificate;
    }

  async receiveCertificate(certificate, signature) {
      const isValid = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
      
      if (!isValid) {
          throw new Error('Invalid certificate signature.');
      }
    
      this.certs[certificate.username] = certificate;
  }

  async sendMessage(name, plaintext) {
    //gen symmetric key
    const sharedDHOutput = await this.generateSharedDHKey(name);

    //gen chaining key
    let chainingKey = await this.generateChainingKey(name, sharedDHOutput);

    const HLDFKey = await HKDF(sharedDHOutput, chainingKey, HKDFCONST);
    const sendingKey = HLDFKey[0]; 
    const nextChainingKey = HLDFKey[1];
    this.conns[name] = { chainingKey: nextChainingKey };

    // gen message key
    const receiverNonce = genRandomSalt();
    const messageKey = await HMACtoAESKey(sendingKey, HMACCONST);

    // gen gov key and setup
    const govKeypair = await generateEG();
    const govSharedDH = await computeDH(govKeypair.sec, this.govPublicKey);
    const govEncryptionKey = await HMACtoAESKey(govSharedDH, govEncryptionDataStr);
    const messageKeyBytes = await HMACtoAESKey(sendingKey, HMACCONST, true);
    const govEncryptionNonce = genRandomSalt();
    const govEncryptedData = await encryptWithGCM(govEncryptionKey, messageKeyBytes, govEncryptionNonce);

    const header = {
        vGov: govKeypair.pub,
        cGov: govEncryptedData,
        ivGov: govEncryptionNonce,
        receiverIV: receiverNonce,
        publicKey: this.EGKeyPair.pub
      };

      const ciphertext = await encryptWithGCM(messageKey, plaintext, receiverNonce, JSON.stringify(header));

      return [header, ciphertext];
  }

  async receiveMessage(name, [header, ciphertext]) {

  const sharedDHOutput = await this.generateSharedDHKey(name);

  let chainingKey = await this.generateChainingKey(name, sharedDHOutput);
  
  const HLDFKey = await HKDF(sharedDHOutput, chainingKey, HKDFCONST);
  const receivingKey = HLDFKey[0]; 

  const nextChainingKey = HLDFKey[1];
  this.conns[name] = { chainingKey: nextChainingKey };

  const receiverIV = header.receiverIV;
  const messageKey = await HMACtoAESKey(receivingKey, HMACCONST);
  const decryptedMessage = await decryptWithGCM(messageKey, ciphertext, receiverIV, JSON.stringify(header));

  return bufferToString(decryptedMessage);
  }
}

module.exports = {
  MessengerClient
}

