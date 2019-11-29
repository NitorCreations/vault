const AWS = require('aws-sdk');
const crypto = require('crypto');

const ALGORITHMS = Object.freeze({
  crypto: 'AES-256-CTR',
  authCrypto: 'id-aes256-GCM',
  kms: 'AES_256'
});
const STATIC_IV = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256]);
const ENCODING = 'UTF-8';

const createRequestObject = (bucketName, key) => Object.freeze({
  Bucket: bucketName,
  Key: key
});

const createKeyRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.key`);

const createEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.encrypted`);

const createAuthEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.aesgcm.encrypted`);

const createMetaRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.meta`);

const createDecipher = (meta, decryptedKey) => {
  return meta === 'nometa' ?
    crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV) :
    crypto.createDecipheriv(ALGORITHMS.authCrypto, decryptedKey, Buffer.from(JSON.parse(meta.Body).nonce, "base64")).setAAD(meta.Body);
};

const createVaultClient = (options) => {
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

  const ensureCredentials = () => {
    if (AWS.config.credentials) {
      return Promise.resolve();
    }
    return new AWS.CredentialProviderChain([
      new AWS.SharedIniFileCredentials(),
      new AWS.EnvironmentCredentials('AWS'),
      new AWS.EC2MetadataCredentials({
        httpOptions: { timeout: 5000 },
        maxRetries: 10,
        retryDelayOptions: { base: 200 }
      })
    ]).resolvePromise();
  };

  return {
    lookup: (name) => ensureCredentials()
      .then(() =>
        Promise.all([
          s3.getObject(createKeyRequestObject(bucketName, name)).promise()
            .then(encryptedKey => kms.decrypt({ CiphertextBlob: encryptedKey.Body }).promise()),
          s3.getObject(createAuthEncryptedValueRequestObject(bucketName, name)).promise() 
            .catch(e => s3.getObject(createEncryptedValueRequestObject(bucketName, name)).promise()),
          s3.getObject(createMetaRequestObject(bucketName, name)).promise().catch(e => "nometa")
        ])
      )
      .then(keyValueAndMeta => {
        const decryptedKey = keyValueAndMeta[0].Plaintext;
        const encryptedValue = keyValueAndMeta[1].Body.slice(0, -16);
        const authTag = keyValueAndMeta[1].Body.slice(-16);
        const meta = keyValueAndMeta[2];
        const decipher = createDecipher(meta, decryptedKey).setAuthTag(authTag);
        const value = decipher.update(encryptedValue, null, ENCODING);

        try {
          decipher.final(ENCODING);
        } catch (e) {
          return Promise.reject(e);
        }
        return Promise.resolve(value);
      }),

    store: (name, data) => ensureCredentials()
      .then(() =>
        kms.generateDataKey({
          KeyId: vaultKey,
          KeySpec: ALGORITHMS.kms
        }).promise())
      .then((dataKey) => {
        const nonce = crypto.randomBytes(12);
        const aad = Buffer.from(JSON.stringify({
          alg: "AESGCM",
          nonce: nonce.toString("base64")
        }));
        const cipher = crypto.createCipheriv(ALGORITHMS.authCrypto, dataKey.Plaintext, nonce).setAAD(aad);
        const authValue = cipher.update(data, ENCODING);
        cipher.final(ENCODING);
        return Promise.resolve({
          key: dataKey.CiphertextBlob,
          value: crypto.createCipheriv(ALGORITHMS.crypto, dataKey.Plaintext, STATIC_IV).update(data, ENCODING),
          authValue: Buffer.concat([authValue, cipher.getAuthTag()]),
          meta: aad
        }
      )})
      .then((keyAndValue) =>
        Promise.all([
          writeObject(createKeyRequestObject(bucketName, name), keyAndValue.key),
          writeObject(createEncryptedValueRequestObject(bucketName, name), keyAndValue.value),
          writeObject(createAuthEncryptedValueRequestObject(bucketName, name), keyAndValue.authValue),
          writeObject(createMetaRequestObject(bucketName, name), keyAndValue.meta)
        ])),

    delete: (name) => ensureCredentials()
      .then(() =>
        Promise.all([
          s3.deleteObject(createEncryptedValueRequestObject(bucketName, name)).promise(),
          s3.deleteObject(createKeyRequestObject(bucketName, name)).promise(),
          s3.deleteObject(createAuthEncryptedValueRequestObject(bucketName, name)).promise().catch(e => e),
          s3.deleteObject(createMetaRequestObject(bucketName, name)).promise().catch(e => e)
        ])),

    exists: (name) => ensureCredentials()
      .then(() =>
        s3.headObject(createEncryptedValueRequestObject(bucketName, name)).promise())
      .then(() => Promise.resolve(true), () => Promise.resolve(false)
    ),

    all: () => ensureCredentials()
      .then(() =>
        s3.listObjectsV2({
          Bucket: bucketName
        }).promise())
      .then((data) => Promise.resolve(data.Contents
        .filter((object) => object.Key.endsWith('.encrypted'))
        .map(object => object.Key.slice(0, -('.encrypted'.length)))))
  };
};

module.exports = createVaultClient;
