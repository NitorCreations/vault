package com.nitorcreations.vault;

import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.util.IOUtils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudformation.model.DescribeStacksRequest;
import com.amazonaws.services.cloudformation.model.DescribeStacksResult;
import com.amazonaws.services.cloudformation.model.Output;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import static java.nio.charset.StandardCharsets.UTF_8;

import static com.amazonaws.services.s3.model.CannedAccessControlList.Private;
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
  private final AmazonS3 s3;
  private final AWSKMS kms;
  private final String bucketName;
  private final String vaultKey;

  private static final String VALUE_OBJECT_SUFFIX = "encrypted";
  private static final String AESGCM_VALUE_OBJECT_SUFFIX = "aesgcm.encrypted";
  private static final String META_VALUE_OBJECT_SUFFIX = "meta";
  private static final String VALUE_OBJECT_NAME_FORMAT = "%s.%s";
  private static final String KEY_OBJECT_NAME_FORMAT = "%s.key";

  @Deprecated
  public VaultClient(AmazonS3Client s3, AWSKMSClient kms, String bucketName, String vaultKey) {
    this((AmazonS3) s3, (AWSKMS) kms, bucketName, vaultKey);
  }

  public VaultClient() {
    this(resolveKeyAndBucket(null, null));
  }

  public VaultClient(String vaultStack) {
    this(resolveKeyAndBucket(vaultStack, null));
  }

  public VaultClient(String vaultStack, Regions region) {
    this(resolveKeyAndBucket(vaultStack, region), region);
  }

  public VaultClient(KeyAndBucket kb) {
    this(kb.vaultBucket, kb.keyArn);
  }

  public VaultClient(KeyAndBucket kb, Regions region) {
    this(kb.vaultBucket, kb.keyArn, region);
  }

  public VaultClient(String vaultBucket, String keyArn) {
    this(AmazonS3ClientBuilder.defaultClient(), AWSKMSClientBuilder.defaultClient(), vaultBucket, keyArn);
  }

  public VaultClient(String vaultBucket, String keyArn, Regions region) {
    this(AmazonS3ClientBuilder.standard().withRegion(region).build(),
         AWSKMSClientBuilder.standard().withRegion(region).build(), vaultBucket, keyArn);
  }

  public VaultClient(AmazonS3 s3, AWSKMS kms, String bucketName, String vaultKey) {
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

  public static KeyAndBucket resolveKeyAndBucket(final String vaultStack, final Regions region) {
    String resolveStack = "vault";
    if (vaultStack == null || vaultStack.isEmpty()) {
      if (System.getenv("VAULT_STACK") != null) {
        resolveStack = System.getenv("VAULT_STACK");
      }
    } else {
      resolveStack = vaultStack;
    }
    AmazonCloudFormation cf;
    if (region != null) {
      cf = AmazonCloudFormationClientBuilder.standard().withRegion(region).build();
    } else {
      cf = AmazonCloudFormationClientBuilder.defaultClient();
    }
    DescribeStacksRequest request = new DescribeStacksRequest();
    request.setStackName(resolveStack);
    DescribeStacksResult result = cf.describeStacks(request);
    String bucket = null, key = null;
    for (Output output : result.getStacks().get(0).getOutputs()) {
      if (output.getOutputKey().equals("vaultBucketName")) {
        bucket = output.getOutputValue();
      } else if (output.getOutputKey().equals("kmsKeyArn")) {
        key = output.getOutputValue();
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
    } catch (AmazonS3Exception | IOException e) {
      try {
        encrypted = readObject(encyptedValueObjectName(name));
        key = readObject(keyObjectName(name));
      } catch (IOException ex) {
        throw new IllegalStateException(String.format("Could not read secret %s from vault", name), ex);
      }
    }

    final ByteBuffer decryptedKey = kms.decrypt(new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(key))).getPlaintext();

    try {
      return decrypt(encrypted, decryptedKey, meta);
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
    return this.s3.doesObjectExist(this.bucketName, keyObjectName(name));
  }

  public void delete(String name) {
    deleteObject(keyObjectName(name));
    deleteObject(encyptedValueObjectName(name));
  }

  public List<String> all() {
    return this.s3.listObjects(this.bucketName).getObjectSummaries().stream()
        .filter(object -> object.getKey().endsWith(VALUE_OBJECT_SUFFIX))
        .map(object -> object.getKey().substring(0, object.getKey().length() - (VALUE_OBJECT_SUFFIX.length() + 1)))
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
    final GenerateDataKeyResult dataKey = kms
        .generateDataKey(new GenerateDataKeyRequest().withKeyId(this.vaultKey).withKeySpec(DataKeySpec.AES_256));
    final Cipher cipher = createCipher(dataKey.getPlaintext(), Cipher.ENCRYPT_MODE);
    final CipherAndAAD aesgcmcipher = createAESGCMCipher(dataKey.getPlaintext());

    return new EncryptResult(dataKey.getCiphertextBlob().array(), cipher.doFinal(data),
        aesgcmcipher.cipher.doFinal(data), aesgcmcipher.aad);
  }

  private byte[] decrypt(byte[] encrypted, ByteBuffer decryptedKey, byte[] meta) throws GeneralSecurityException, IOException {
    if (meta != null) {
      return createAESGCMCipher(decryptedKey, meta).doFinal(encrypted);
    }
    return createCipher(decryptedKey, Cipher.DECRYPT_MODE).doFinal(encrypted);
  }

  public byte[] directDecrypt(byte[] data) {
    return kms.decrypt(new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(data))).getPlaintext().array();
  }
  public byte[] directEncrypt(byte[] data) {
    return kms.encrypt(new EncryptRequest().withKeyId(this.vaultKey).withPlaintext(ByteBuffer.wrap(data))).getCiphertextBlob().array();
  }
  private static Cipher createCipher(final ByteBuffer unencryptedKey, final int encryptMode) throws GeneralSecurityException {
    final byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256 };
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

    cipher.init(encryptMode, new SecretKeySpec(unencryptedKey.array(), "AES"), new IvParameterSpec(iv));
    return cipher;
  }

  private static CipherAndAAD createAESGCMCipher(final ByteBuffer unencryptedKey) throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    random.nextBytes(nonce);
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(unencryptedKey.array(), "AES"), spec);
    byte[] aad = ("{\"alg\":\"AESGCM\",\"nonce\":\"" + Base64.getEncoder().encodeToString(nonce) + "\"}")
        .getBytes(UTF_8);
    cipher.updateAAD(aad);
    return new CipherAndAAD(cipher, aad);
  }

  private static Cipher createAESGCMCipher(final ByteBuffer unencryptedKey, byte[] aad) throws GeneralSecurityException, IOException {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    Map<String, String> map = new ObjectMapper().readValue(new String(aad, UTF_8),
          new TypeReference<Map<String, String>>() {});
    final byte[] nonce = Base64.getDecoder().decode(map.get("nonce"));
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(unencryptedKey.array(), "AES"), spec);
    cipher.updateAAD(aad);
    return cipher;
  }

  private void writeObject(String key, byte[] value) {
    this.s3.putObject(new PutObjectRequest(this.bucketName, key, new ByteArrayInputStream(value), new ObjectMetadata()).withCannedAcl(Private));
  }

  private byte[] readObject(String key) throws IOException {
    return IOUtils.toByteArray(this.s3.getObject(new GetObjectRequest(this.bucketName, key)).getObjectContent());
  }

  private void deleteObject(String key) {
    this.s3.deleteObject(new DeleteObjectRequest(this.bucketName, key));
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
