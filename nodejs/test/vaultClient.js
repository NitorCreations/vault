const AWS = require('aws-sdk-mock');
const sinon = require('sinon');
require('should');
require('should-sinon');
const VaultClient = require('../lib/vaultClient');
const crypto = require("crypto");

const VAULT_KEY_FIXTURE = 'vaultKey';
const BUCKET_NAME_FIXTURE = 'bucket';
const SECRET_NAME_FIXTURE = 'name';
const ENCRYPTED_KEY_FIXTURE = 'key';
const DATA_FIXTURE = 'value';

describe('VaultClient', () => {
  let vaultClient;
  const getObjectSpy = sinon.stub();
  const decryptSpy = sinon.stub();
  const putObjectSpy = sinon.stub();
  const generateDataKeySpy = sinon.stub();
  const headObjectSpy = sinon.stub();
  const listObjectsSpy = sinon.stub();
  const deleteObjectSpy = sinon.stub();

  before(() => {
    AWS.mock('S3', 'getObject', getObjectSpy);
    AWS.mock('S3', 'putObject', putObjectSpy);
    AWS.mock('S3', 'headObject', headObjectSpy);
    AWS.mock('S3', 'listObjectsV2', listObjectsSpy);
    AWS.mock('S3', 'deleteObject', deleteObjectSpy);
    AWS.mock('KMS', 'decrypt', decryptSpy);
    AWS.mock('KMS', 'generateDataKey', generateDataKeySpy);
    AWS.mock('CredentialProviderChain', 'resolvePromise', sinon.stub().resolves())
  });

  beforeEach(() => {
    vaultClient = VaultClient({
      bucketName: BUCKET_NAME_FIXTURE,
      vaultKey: VAULT_KEY_FIXTURE
    });
    return vaultClient.setupCredentials();
  });

  after(() => {
    AWS.restore();
  });

  describe('factory', () => {
    it('returns an object', () => {
      vaultClient.should.be.an.Object();
    });
  });

  describe('lookup', () => {
    beforeEach(() => {
      getObjectSpy
        .onCall(0)
        .yields(null, { Body: ENCRYPTED_KEY_FIXTURE })
        .onCall(1)
        .yields(null, { Body: 'foo' });

      decryptSpy.yields(null, {
        Plaintext: crypto.randomBytes(32)
      });
    });

    afterEach(() => {
      getObjectSpy.reset();
      decryptSpy.reset();
    });

    it('reads encrypted value from S3', () => vaultClient.lookup(SECRET_NAME_FIXTURE)
      .then(() => getObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + '.encrypted' })));

    it('reads encrypted key from S3', () => vaultClient.lookup(SECRET_NAME_FIXTURE)
      .then(() => getObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + '.key' })));

    it('reads encrypted key and value from the correct bucket', () => vaultClient.lookup(SECRET_NAME_FIXTURE)
      .then(() => getObjectSpy.should.have.been.alwaysCalledWithMatch({ Bucket: BUCKET_NAME_FIXTURE })));

    it('decrypts the encrypted key using KMS', () => vaultClient.lookup(SECRET_NAME_FIXTURE)
      .then(() => decryptSpy.should.have.been.calledWithMatch({ CiphertextBlob: ENCRYPTED_KEY_FIXTURE })));

    it('resolves to a string promise', () => vaultClient.lookup(SECRET_NAME_FIXTURE)
      .then((result) => result.should.be.a.String()));
  });

  describe('store', () => {
    beforeEach(() => {
      putObjectSpy.yields();

      generateDataKeySpy.yields(null, {
        Plaintext: crypto.randomBytes(32),
        CiphertextBlob: crypto.randomBytes(32)
      });
    });

    it('Writes encrypted value to S3', () => vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
      .then(() => putObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + ".encrypted" })));

    it('Writes encryption key to S3', () => vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
      .then(() => putObjectSpy.should.have.been.calledWithMatch({ Key: SECRET_NAME_FIXTURE + ".key" })));

    it('Writes key and value to correct bucket', () => vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
      .then(() => putObjectSpy.should.have.been.alwaysCalledWithMatch({ Bucket: BUCKET_NAME_FIXTURE })));

    it('Encrypts value using the correct vault key', () => vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE)
      .then(() => generateDataKeySpy.should.have.been.calledWithMatch({ KeyId: VAULT_KEY_FIXTURE })));
  });

  describe('exists', () => {
    describe('when object exists' , () => {
      beforeEach(() => headObjectSpy.yields(null, {}));

      it('resolves to true', () => {
        return vaultClient.exists(SECRET_NAME_FIXTURE)
          .then((exists) => {
            exists.should.be.true();
          });
      });
    });

    describe('when object does not exist', () => {
      beforeEach(() => headObjectSpy.yields({}));

      it('resolves to false', () => {
        return vaultClient.exists(SECRET_NAME_FIXTURE)
          .then((exists) => {
            exists.should.be.false();
          });
      });
    });
  });

  describe('all', () => {
    beforeEach(() => {
      listObjectsSpy.yields(null, { Contents: [
        {
          Key: 'first.encrypted'
        },
        {
          Key: 'second.key'
        },
        {
          Key: 'second.encrypted'
        },
        {
          Key: 'first.key'
        }
      ]});
    });

    it('resolves to an Array of names', () => vaultClient.all().then(all => all.should.be.an.Array()));

    it('resolves to an Array of correct size', () => vaultClient.all().then(all => all.should.have.property('length', 2)));

    it('resolves to an Array with correct names', () => vaultClient.all().then(all => {
      all.should.containEql('first');
      all.should.containEql('second');
    }))
  });

  describe('delete', () => {
    beforeEach(() => {
      deleteObjectSpy.yields(null, {});
    });

    it('deletes the encrypted value from S3', () => vaultClient.delete(ENCRYPTED_KEY_FIXTURE)
      .then(() => deleteObjectSpy.should.have.been.calledWithMatch({
        Key: ENCRYPTED_KEY_FIXTURE + '.encrypted'
      })));

    it('deletes the key from S3', () => vaultClient.delete(ENCRYPTED_KEY_FIXTURE)
      .then(() => deleteObjectSpy.should.have.been.calledWithMatch({
        Key: ENCRYPTED_KEY_FIXTURE + '.key'
      })));

    it('deletes the value and the key from the correct bucket', () => vaultClient.delete(ENCRYPTED_KEY_FIXTURE)
      .then(() => deleteObjectSpy.should.have.been.alwaysCalledWithMatch({
        Bucket: BUCKET_NAME_FIXTURE
      })));
  });
});