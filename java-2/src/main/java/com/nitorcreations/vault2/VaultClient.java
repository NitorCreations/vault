package com.nitorcreations.vault2;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksRequest;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksResponse;
import software.amazon.awssdk.services.cloudformation.model.Output;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.regions.Region;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.s3.model.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import static java.nio.charset.StandardCharsets.UTF_8;

import static java.util.stream.Collectors.toList;

public class VaultClient {
  public static final int GCM_NONCE_LENGTH = 12;
  public static final int GCM_TAG_LENGTH = 16;
  private static final SecureRandom random;
  static {
    try {
      random = SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException nao) {
      throw new RuntimeException("Failed to initialize random", nao);
    }
  }
  private final S3Client s3;
  private final KmsClient kms;
  private final String bucketName;
  private final String vaultKey;

  private static final String VALUE_OBJECT_SUFFIX = "encrypted";
  private static final String AESGCM_VALUE_OBJECT_SUFFIX = "aesgcm.encrypted";
  private static final String META_VALUE_OBJECT_SUFFIX = "meta";
  private static final String VALUE_OBJECT_NAME_FORMAT = "%s.%s";
  private static final String KEY_OBJECT_NAME_FORMAT = "%s.key";

  public VaultClient() {
    this(resolveKeyAndBucket(null, null));
  }

  public VaultClient(String vaultStack) {
    this(resolveKeyAndBucket(vaultStack, null));
  }

  public VaultClient(String vaultStack, Region region) {
    this(resolveKeyAndBucket(vaultStack, region), region);
  }

  public VaultClient(KeyAndBucket kb) {
    this(kb.vaultBucket, kb.keyArn);
  }

  public VaultClient(KeyAndBucket kb, Region region) {
    this(kb.vaultBucket, kb.keyArn, region);
  }

  public VaultClient(String vaultBucket, String keyArn) {
    this(S3Client.builder().build(), KmsClient.builder().build(), vaultBucket, keyArn);
  }

  public VaultClient(String vaultBucket, String keyArn, Region region) {
    this(S3Client.builder().region(region).build(),
         KmsClient.builder().region(region).build(), vaultBucket, keyArn);
  }

  public VaultClient(S3Client s3, KmsClient kms, String bucketName, String vaultKey) {
    if (s3 == null) {
      throw new IllegalArgumentException("S3 client is needed");
    }
    if (kms == null) {
      throw new IllegalArgumentException("KMS client is needed");
    }
    if (bucketName == null) {
      throw new IllegalArgumentException("Bucket name is needed");
    }
    this.s3 = s3;
    this.kms = kms;
    this.bucketName = bucketName;
    this.vaultKey = vaultKey;
  }

  public static KeyAndBucket resolveKeyAndBucket(final String vaultStack, final Region region) {
    String resolveStack = "vault";
    if (vaultStack == null || vaultStack.isEmpty()) {
      if (System.getenv("VAULT_STACK") != null) {
        resolveStack = System.getenv("VAULT_STACK");
      }
    } else {
      resolveStack = vaultStack;
    }
    CloudFormationClient cf;
    if (region != null) {
      cf = CloudFormationClient.builder().region(region).build();
    } else {
      cf = CloudFormationClient.builder().build();
    }
    DescribeStacksRequest request = DescribeStacksRequest.builder().stackName(resolveStack).build();
    DescribeStacksResponse result = cf.describeStacks(request);
    String bucket = null, key = null;
    for (Output output : result.stacks().get(0).outputs()) {
      if (output.outputKey().equals("vaultBucketName")) {
        bucket = output.outputValue();
      } else if (output.outputKey().equals("kmsKeyArn")) {
        key = output.outputValue();
      }
    }
    return new KeyAndBucket(key, bucket);
  }
  public String lookup(String name) throws VaultException {
    return new String(lookupBytes(name), UTF_8);
  }
  public byte[] lookupBytes(String name) throws VaultException {
    byte[] encrypted, key, meta = null;
    try {
      meta = readObject(metaValueObjectName(name));
      encrypted = readObject(aesgcmValueObjectName(name));
      key = readObject(keyObjectName(name));
    } catch (S3Exception | IOException e) {
      try {
        encrypted = readObject(encyptedValueObjectName(name));
        key = readObject(keyObjectName(name));
      } catch (IOException ex) {
        throw new IllegalStateException(String.format("Could not read secret %s from vault", name), ex);
      }
    }

    final SdkBytes decryptedKey = kms.decrypt(DecryptRequest.builder().ciphertextBlob(SdkBytes.fromByteArray(key))
            .build()).plaintext();

    try {
      return decrypt(encrypted, ByteBuffer.wrap(decryptedKey.asByteArray()), meta);
    } catch (GeneralSecurityException | IOException e) {
      throw new VaultException(String.format("Unable to decrypt secret %s", name), e);
    }
  }

  public void store(String name, String data) throws VaultException {
    store(name, data.getBytes(UTF_8));
  }
  public void store(String name, byte[] data) throws VaultException {
    EncryptResult encrypted;
    try {
      encrypted = encrypt(data);
    } catch (GeneralSecurityException e) {
      throw new VaultException(String.format("Unable to encrypt secret %s:%s", name, data), e);
    }
    writeObject(keyObjectName(name), encrypted.encryptedKey);
    writeObject(encyptedValueObjectName(name), encrypted.aesCipherText);
    writeObject(aesgcmValueObjectName(name), encrypted.aesGCMCipherText);
    writeObject(metaValueObjectName(name), encrypted.aesGCMAAD);
  }

  public boolean exists(String name) {
    try {
      return this.s3.headObject(HeadObjectRequest.builder().bucket(this.bucketName).key(keyObjectName(name)).build()).contentLength() > 0;
    } catch (NoSuchKeyException e) {
      return false;
    }
  }

  public void delete(String name) {
    deleteObject(keyObjectName(name));
    deleteObject(encyptedValueObjectName(name));
  }

  public List<String> all() {
    return this.s3.listObjectsV2(ListObjectsV2Request.builder().bucket(this.bucketName).build()).contents().stream()
        .filter(object -> object.key().endsWith(VALUE_OBJECT_SUFFIX))
        .map(object -> object.key().substring(0, object.key().length() - (VALUE_OBJECT_SUFFIX.length() + 1)))
        .collect(toList());
  }

  private static String encyptedValueObjectName(String name) {
    return String.format(VALUE_OBJECT_NAME_FORMAT, name, VALUE_OBJECT_SUFFIX);
  }

  private static String metaValueObjectName(String name) {
    return String.format(VALUE_OBJECT_NAME_FORMAT, name, META_VALUE_OBJECT_SUFFIX);
  }

  private static String aesgcmValueObjectName(String name) {
    return String.format(VALUE_OBJECT_NAME_FORMAT, name, AESGCM_VALUE_OBJECT_SUFFIX);
  }

  private static String keyObjectName(String name) {
    return String.format(KEY_OBJECT_NAME_FORMAT, name);
  }

  private EncryptResult encrypt(byte[] data) throws GeneralSecurityException {
    final GenerateDataKeyResponse dataKey = kms
        .generateDataKey(GenerateDataKeyRequest.builder().keyId(this.vaultKey).keySpec(DataKeySpec.AES_256).build());
    final Cipher cipher = createCipher(ByteBuffer.wrap(dataKey.plaintext().asByteArray()), Cipher.ENCRYPT_MODE);
    final CipherAndAAD aesgcmcipher = createAESGCMCipher(ByteBuffer.wrap(dataKey.plaintext().asByteArray()));

    return new EncryptResult(dataKey.ciphertextBlob().asByteArray(), cipher.doFinal(data),
        aesgcmcipher.cipher.doFinal(data), aesgcmcipher.aad);
  }

  private byte[] decrypt(byte[] encrypted, ByteBuffer decryptedKey, byte[] meta) throws GeneralSecurityException,
          IOException {
    if (meta != null) {
      return createAESGCMCipher(decryptedKey, meta).doFinal(encrypted);
    }
    return createCipher(decryptedKey, Cipher.DECRYPT_MODE).doFinal(encrypted);
  }

  public byte[] directDecrypt(byte[] data) {
    return kms.decrypt(DecryptRequest.builder().ciphertextBlob(SdkBytes.fromByteArray(data)).build()).plaintext()
            .asByteArray();
  }
  public byte[] directEncrypt(byte[] data) {
    return kms.encrypt(EncryptRequest.builder().keyId(this.vaultKey).plaintext(SdkBytes.fromByteArray(data)).build())
            .ciphertextBlob().asByteArray();
  }
  private static Cipher createCipher(final ByteBuffer unencryptedKey, final int encryptMode) throws GeneralSecurityException {
    final byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256 };
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

    cipher.init(encryptMode, new SecretKeySpec(unencryptedKey.array(), "AES"), new IvParameterSpec(iv));
    return cipher;
  }

  private static CipherAndAAD createAESGCMCipher(final ByteBuffer unencryptedKey) throws GeneralSecurityException {
    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    random.nextBytes(nonce);
    byte[] aad = ("{\"alg\":\"AESGCM\",\"nonce\":\"" + Base64.getEncoder().encodeToString(nonce) + "\"}")
        .getBytes(UTF_8);
    return new CipherAndAAD(createAESGCMCipher(unencryptedKey, aad, nonce), aad);
  }

  private static Cipher createAESGCMCipher(final ByteBuffer unencryptedKey, byte[] aad) throws GeneralSecurityException,
          IOException {
    Map<String, String> map = new ObjectMapper().readValue(new String(aad, UTF_8),
          new TypeReference<Map<String, String>>() {});
    final byte[] nonce = Base64.getDecoder().decode(map.get("nonce"));
    return createAESGCMCipher(unencryptedKey, aad, nonce);
  }

  private static Cipher createAESGCMCipher(final ByteBuffer unencryptedKey, byte[] aad, byte[] nonce)
          throws GeneralSecurityException {
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(unencryptedKey.array(), "AES"), spec);
      cipher.updateAAD(aad);
      return cipher;
  }

  private void writeObject(String key, byte[] value) {
    this.s3.putObject(PutObjectRequest.builder().bucket(this.bucketName).key(key).acl(ObjectCannedACL.PRIVATE).build(),
            RequestBody.fromBytes(value));
  }

  private byte[] readObject(String key) throws IOException {
    return this.s3.getObject(GetObjectRequest.builder().bucket(this.bucketName).key(key).build()).readAllBytes();
  }

  private void deleteObject(String key) {
    this.s3.deleteObject(DeleteObjectRequest.builder().bucket(this.bucketName).key(key).build());
  }

  private static class CipherAndAAD {
    public final Cipher cipher;
    public final byte[] aad;
    public CipherAndAAD(Cipher cipher, byte[] aad) {
      this.cipher = cipher;
      this.aad = aad;
    }
  }
  private static class EncryptResult {
    public final byte[] encryptedKey;
    public final byte[] aesCipherText;
    public final byte[] aesGCMCipherText;
    public final byte[] aesGCMAAD;
    public EncryptResult(byte[] encryptedKey, byte[] aesCipherText,
                         byte[] aesGCMCipherText, byte[] aesGCMAAD) {
      this.encryptedKey = encryptedKey;
      this.aesCipherText = aesCipherText;
      this.aesGCMCipherText = aesGCMCipherText;
      this.aesGCMAAD = aesGCMAAD;
    }
  }
  public static class KeyAndBucket {
    public final String keyArn;
    public final String vaultBucket;
    public KeyAndBucket(String keyArn, String vaultBucket) {
      this.keyArn = keyArn;
      this.vaultBucket = vaultBucket;
    }
  }
}
