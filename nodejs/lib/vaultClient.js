const AWS = require('aws-sdk');
const crypto = require('crypto');

const ALGORITHMS = Object.freeze({
  crypto: 'AES-256-CTR',
  kms: 'AES_256'
});
const STATIC_IV = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256]);
const ENCODING = 'UTF-8';

const createRequestObject = (bucketName, key) => Object.freeze({
  Bucket: bucketName,
  Key: key
});

const createKeyRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.key`);

const createEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.encrypted`);

createVaultClient = (options) => {
  const bucketName = options.bucketName;
  const vaultKey = options.vaultKey;
  const region = options.region || process.env.AWS_DEFAULT_REGION;

  const s3 = new AWS.S3({
    region: region
  });
  const kms = new AWS.KMS({
    region: region
  });

  const writeObject = (base, value) => s3.putObject(Object.assign({
    Body: value,
    ACL: 'private'
  }, base)).promise();

  return {
    setupCredentials: () => {
      return new AWS.CredentialProviderChain([
        new AWS.SharedIniFileCredentials(),
        new AWS.EnvironmentCredentials('AWS'),
        new AWS.EC2MetadataCredentials({
          httpOptions: { timeout: 5000 },
          maxRetries: 10,
          retryDelayOptions: { base: 200 }
        })
      ]).resolvePromise();
    },

    lookup: (name) => Promise.all([
      s3.getObject(createKeyRequestObject(bucketName, name)).promise()
        .then((encryptedKey) => {
          return kms.decrypt({ CiphertextBlob: encryptedKey.Body }).promise();
        }),
      s3.getObject(createEncryptedValueRequestObject(bucketName, name)).promise()
    ]).then((keyAndValue) => {
      const decryptedKey = keyAndValue[0].Plaintext;
      const encryptedValue = keyAndValue[1].Body;
      const decipher = crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV);
      return Promise.resolve(decipher.update(encryptedValue, ENCODING, ENCODING));
    }),

    store: (name, data) => kms.generateDataKey({
      KeyId: vaultKey,
      KeySpec: ALGORITHMS.kms
    }).promise().then((dataKey) => {
      const cipher = crypto.createCipheriv(ALGORITHMS.crypto, dataKey.Plaintext, STATIC_IV);
      return Promise.resolve({ key: dataKey.CiphertextBlob, value: cipher.update(data, null, ENCODING) });
    }).then((keyAndValue) => {
      return Promise.all([
        writeObject(createKeyRequestObject(bucketName, name), keyAndValue.key),
        writeObject(createEncryptedValueRequestObject(bucketName, name), keyAndValue.value)
      ]);
    }),

    delete: (name) => Promise.all([
      s3.deleteObject(createEncryptedValueRequestObject(bucketName, name)).promise(),
      s3.deleteObject(createKeyRequestObject(bucketName, name)).promise()
    ]),

    exists: (name) => s3.headObject(createEncryptedValueRequestObject(bucketName, name)).promise().then(
      () => Promise.resolve(true),
      () => Promise.resolve(false)
    ),

    all: () => s3.listObjectsV2({
      Bucket: bucketName
    }).promise().then((data) => {
      return Promise.resolve(data.Contents
        .filter((object) => object.Key.endsWith('.encrypted'))
        .map(object => object.Key.slice(0, -('.encrypted'.length))));
    })
  }
};

module.exports = createVaultClient;
