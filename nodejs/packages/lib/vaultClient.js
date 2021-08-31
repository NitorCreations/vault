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

const staticSuffix = `.encrypted`;
const createEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}${staticSuffix}`);

const aesgcmSuffix = `.aesgcm.encrypted`;
const createAuthEncryptedValueRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}${aesgcmSuffix}`);

const createMetaRequestObject = (bucketName, name) => createRequestObject(bucketName, `${name}.meta`);

const nometa = 'nometa';

const createDecipher = (meta, decryptedKey, authTag) => {
  return meta === nometa ?
    crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV) :
    crypto.createDecipheriv(ALGORITHMS.authCrypto, decryptedKey, Buffer.from(JSON.parse(meta.Body).nonce, "base64")).setAAD(meta.Body).setAuthTag(authTag);
};

const writeObject = (s3, base, value) => s3.putObject(Object.assign({
  Body: value,
  ACL: 'private'
}, base)).promise();

module.exports = {
  lookup: (name, options) => {
    const { region, bucketName } = options;

    const s3 = new AWS.S3({
      region,
    });

    const kms = new AWS.KMS({
      region,
    });

    return Promise.all([
      s3.getObject(createKeyRequestObject(bucketName, name)).promise()
        .then(encryptedKey => kms.decrypt({ CiphertextBlob: encryptedKey.Body }).promise()),
      s3.getObject(createAuthEncryptedValueRequestObject(bucketName, name)).promise()
        .catch(() => s3.getObject(createEncryptedValueRequestObject(bucketName, name)).promise()),
      s3.getObject(createMetaRequestObject(bucketName, name)).promise().catch(() => nometa)
    ])
      .then(keyValueAndMeta => {
        const decryptedKey = keyValueAndMeta[0].Plaintext;
        const encryptedValue = keyValueAndMeta[1].Body.slice(0, -16);
        const authTag = keyValueAndMeta[1].Body.slice(-16);
        const meta = keyValueAndMeta[2];
        const decipher = createDecipher(meta, decryptedKey, authTag);
        const value = decipher.update(encryptedValue, null, ENCODING);

        try {
          decipher.final(ENCODING);
        } catch (e) {
          return Promise.reject(e);
        }
        return Promise.resolve(value);
      })
  },

  store: (name, data, options) => {
    const { region, vaultKey, bucketName } = options;
    const kms = new AWS.KMS({
      region,
    });
    const s3 = new AWS.S3({
      region,
    });
    return kms.generateDataKey({
      KeyId: vaultKey,
      KeySpec: ALGORITHMS.kms
    }).promise()
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
        )
      })
      .then((keyAndValue) =>
        Promise.all([
          writeObject(s3, createKeyRequestObject(bucketName, name), keyAndValue.key),
          writeObject(s3, createEncryptedValueRequestObject(bucketName, name), keyAndValue.value),
          writeObject(s3, createAuthEncryptedValueRequestObject(bucketName, name), keyAndValue.authValue),
          writeObject(s3, createMetaRequestObject(bucketName, name), keyAndValue.meta)
        ]));
  },

  delete: (name, options) => {
    const { region, bucketName } = options;
    const s3 = new AWS.S3({
      region,
    });
    return Promise.all([
      s3.deleteObject(createEncryptedValueRequestObject(bucketName, name)).promise(),
      s3.deleteObject(createKeyRequestObject(bucketName, name)).promise(),
      s3.deleteObject(createAuthEncryptedValueRequestObject(bucketName, name)).promise().catch(e => e),
      s3.deleteObject(createMetaRequestObject(bucketName, name)).promise().catch(e => e)
    ]);
  },

  exists: (name, options) => {
    const { region, bucketName } = options;
    const s3 = new AWS.S3({
      region,
    });
    return s3.headObject(createEncryptedValueRequestObject(bucketName, name)).promise()
      .then(() => Promise.resolve(true), () => Promise.resolve(false));
  },

  all: (options) => {
    const { region, bucketName } = options;
    const s3 = new AWS.S3({
      region,
    });
    return s3.listObjectsV2({
      Bucket: bucketName
    }).promise()
      .then(data => Promise.resolve([...new Set(data.Contents
        .filter(object => object.Key.endsWith(aesgcmSuffix) || object.Key.endsWith(staticSuffix))
        .map(object => object.Key.slice(0, -(object.Key.endsWith(aesgcmSuffix) ? aesgcmSuffix.length : staticSuffix.length))))]))
  }
};
