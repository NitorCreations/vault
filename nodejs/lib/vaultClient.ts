import crypto from "crypto";
import { Options } from "./loadOptions";
import {
  GetObjectCommandOutput,
  PutObjectCommandInput,
  S3,
} from "@aws-sdk/client-s3";
import { KMS } from "@aws-sdk/client-kms";

const ALGORITHMS = Object.freeze({
  crypto: "AES-256-CTR",
  authCrypto: "aes-256-gcm",
  kms: "AES_256",
});
const STATIC_IV = Buffer.from([
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  1337 / 256,
  1337 % 256,
]);
const ENCODING = "utf-8";
type RequestObject = Readonly<{
  Bucket: string;
  Key: string;
}>;
const createRequestObject = (bucketName: string, key: string): RequestObject =>
  Object.freeze({
    Bucket: bucketName,
    Key: key,
  });

const createKeyRequestObject = (bucketName: string, name: string) =>
  createRequestObject(bucketName, `${name}.key`);

const staticSuffix = `.encrypted`;
const createEncryptedValueRequestObject = (bucketName: string, name: string) =>
  createRequestObject(bucketName, `${name}${staticSuffix}`);

const aesgcmSuffix = `.aesgcm.encrypted`;
const createAuthEncryptedValueRequestObject = (
  bucketName: string,
  name: string
) => createRequestObject(bucketName, `${name}${aesgcmSuffix}`);

const createMetaRequestObject = (bucketName: string, name: string) =>
  createRequestObject(bucketName, `${name}.meta`);

const nometa = "nometa";

const createDecipher = async (
  meta: GetObjectCommandOutput | string,
  decryptedKey: crypto.CipherKey,
  authTag: NodeJS.ArrayBufferView
) =>
  meta === nometa || typeof meta === "string"
    ? crypto.createDecipheriv(ALGORITHMS.crypto, decryptedKey, STATIC_IV)
    : crypto
        .createDecipheriv(
          ALGORITHMS.authCrypto,
          decryptedKey,
          Buffer.from(
            JSON.parse(await meta.Body!.transformToString()).nonce,
            "base64"
          )
        )
        .setAAD(await meta.Body!.transformToByteArray())
        .setAuthTag(authTag);

const writeObject = (
  s3: S3,
  base: RequestObject,
  value: PutObjectCommandInput["Body"]
) =>
  s3.putObject({
    ...base,
    Body: value,
    ACL: "private",
  });
export default {
  lookup: async (name: string, options: Options) => {
    const { bucketName } = options;

    const s3 = new S3({});

    const kms = new KMS({});

    const [decryptedKeyRes, encryptedValRes, meta] = await Promise.all([
      s3
        .getObject(createKeyRequestObject(bucketName, name))
        .then((encryptedKey) => {
          if (!encryptedKey) {
            throw Error("");
          }

          return kms.decrypt({
            CiphertextBlob: encryptedKey.Body as unknown as Uint8Array,
          });
        }),
      s3
        .getObject(createAuthEncryptedValueRequestObject(bucketName, name))
        .catch(() =>
          s3.getObject(createEncryptedValueRequestObject(bucketName, name))
        ),
      s3
        .getObject(createMetaRequestObject(bucketName, name))
        .catch(() => nometa),
    ]);
    const decryptedKey = decryptedKeyRes.Plaintext;
    if (!decryptedKey) {
      throw Error(`Error getting decryptedKey ${bucketName}/${name}`);
    }
    const encryptedValueBody = await encryptedValRes.Body?.transformToString();
    if (!encryptedValueBody || typeof encryptedValueBody !== "string") {
      throw Error(`Error getting encryptedValue ${bucketName}/${name}`);
    }
    const encryptedValue = encryptedValueBody?.slice(0, -16);
    const authTag = new TextEncoder().encode(encryptedValueBody?.slice(-16));
    const decipher = await createDecipher(meta, decryptedKey, authTag);
    const value = decipher.update(encryptedValue, undefined, ENCODING);
    try {
      decipher.final(ENCODING);
    } catch (e) {
      return Promise.reject(e);
    }
    return await Promise.resolve(value);
  },

  store: async (name: string, data: string, options: Options) => {
    const { region, vaultKey, bucketName } = options;
    const kms = new KMS({
      region,
    });
    const s3 = new S3({
      region,
    });
    const dataKey = await kms.generateDataKey({
      KeyId: vaultKey,
      KeySpec: ALGORITHMS.kms,
    });
    const nonce = crypto.randomBytes(12);
    const aad = Buffer.from(
      JSON.stringify({
        alg: "AESGCM",
        nonce: nonce.toString("base64"),
      })
    );
    if (typeof dataKey.Plaintext !== "string") {
      console.log(typeof dataKey.Plaintext);
      throw Error("an Error occurred");
    }
    const cipher = crypto
      .createCipheriv(ALGORITHMS.authCrypto, dataKey.Plaintext, nonce)
      .setAAD(aad);
    const authValue = cipher.update(data, ENCODING);
    cipher.final(ENCODING);
    const keyAndValue = await Promise.resolve({
      key: dataKey.CiphertextBlob,
      value: crypto
        .createCipheriv(ALGORITHMS.crypto, dataKey.Plaintext, STATIC_IV)
        .update(data, ENCODING),
      authValue: Buffer.concat([authValue, cipher.getAuthTag()]),
      meta: aad,
    });
    return await Promise.all([
      writeObject(
        s3,
        createKeyRequestObject(bucketName, name),
        keyAndValue.key
      ),
      writeObject(
        s3,
        createEncryptedValueRequestObject(bucketName, name),
        keyAndValue.value
      ),
      writeObject(
        s3,
        createAuthEncryptedValueRequestObject(bucketName, name),
        keyAndValue.authValue
      ),
      writeObject(
        s3,
        createMetaRequestObject(bucketName, name),
        keyAndValue.meta
      ),
    ]);
  },

  delete: (name: string, options: Options) => {
    const { region, bucketName } = options;
    const s3 = new S3({
      region,
    });
    return Promise.all([
      s3.deleteObject(createEncryptedValueRequestObject(bucketName, name)),
      s3.deleteObject(createKeyRequestObject(bucketName, name)),
      s3
        .deleteObject(createAuthEncryptedValueRequestObject(bucketName, name))
        .catch((e) => e),
      s3
        .deleteObject(createMetaRequestObject(bucketName, name))
        .catch((e) => e),
    ]);
  },

  exists: (name: string, options: Options) => {
    const { region, bucketName } = options;
    const s3 = new S3({
      region,
    });
    return s3
      .headObject(createEncryptedValueRequestObject(bucketName, name))
      .then(
        () => Promise.resolve(true),
        () => Promise.resolve(false)
      );
  },

  all: async (options: Options) => {
    const { region, bucketName } = options;
    const s3 = new S3({
      region,
    });
    const data = await s3.listObjectsV2({
      Bucket: bucketName,
    });
    return await Promise.resolve([
      ...new Set(
        data.Contents?.filter(
          (object) =>
            object.Key?.endsWith(aesgcmSuffix) ||
            object.Key?.endsWith(staticSuffix)
        ).map((object_1) =>
          object_1.Key?.slice(
            0,
            -(object_1.Key.endsWith(aesgcmSuffix)
              ? aesgcmSuffix.length
              : staticSuffix.length)
          )
        )
      ),
    ]);
  },
};
