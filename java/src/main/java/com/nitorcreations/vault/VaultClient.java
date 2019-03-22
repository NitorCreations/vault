package com.nitorcreations.vault;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.util.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

import static com.amazonaws.services.s3.model.CannedAccessControlList.Private;
import static java.util.stream.Collectors.toList;

public class VaultClient {

  private final AmazonS3 s3;
  private final AWSKMS kms;
  private final String bucketName;
  private final String vaultKey;

  private static final String VALUE_OBJECT_SUFFIX = "encrypted";
  private static final String VALUE_OBJECT_NAME_FORMAT = "%s.%s";
  private static final String KEY_OBJECT_NAME_FORMAT = "%s.key";

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

  public String lookup(String name) throws VaultException {
    final byte[] encrypted, key;
    try {
      encrypted = readObject(encyptedValueObjectName(name));
      key = readObject(keyObjectName(name));
    } catch (IOException e) {
      throw new IllegalStateException(String.format("Could not read secret %s from vault", name), e);
    }

    final ByteBuffer decryptedKey = kms.decrypt(new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(key))).getPlaintext();

    try {
      return new String(decrypt(encrypted, decryptedKey));
    } catch (GeneralSecurityException e) {
      throw new VaultException(String.format("Unable to decrypt secret %s", name), e);
    }
  }

  public void store(String name, String data) throws VaultException {
    Map.Entry<ByteBuffer, byte[]> encrypted;
    try {
      encrypted = encrypt(data);
    } catch (GeneralSecurityException e) {
      throw new VaultException(String.format("Unable to encrypt secret %s:%s", name, data), e);
    }
    writeObject(keyObjectName(name), encrypted.getKey().array());
    writeObject(encyptedValueObjectName(name), encrypted.getValue());
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

  private static String keyObjectName(String name) {
    return String.format(KEY_OBJECT_NAME_FORMAT, name);
  }

  private Map.Entry<ByteBuffer, byte[]> encrypt(String data) throws GeneralSecurityException {
    final GenerateDataKeyResult dataKey = kms.generateDataKey(new GenerateDataKeyRequest()
        .withKeyId(this.vaultKey)
        .withKeySpec(DataKeySpec.AES_256)
    );
    final Cipher cipher = createCipher(dataKey.getPlaintext(), Cipher.ENCRYPT_MODE);

    return new AbstractMap.SimpleImmutableEntry<>(dataKey.getCiphertextBlob(), cipher.doFinal(data.getBytes()));
  }

  private byte[] decrypt(byte[] encrypted, ByteBuffer decryptedKey) throws GeneralSecurityException {
    return createCipher(decryptedKey, Cipher.DECRYPT_MODE).doFinal(encrypted);
  }

  private static Cipher createCipher(final ByteBuffer unencryptedKey, final int encryptMode) throws GeneralSecurityException {
    final byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1337 / 256, 1337 % 256 };
    final Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

    cipher.init(encryptMode, new SecretKeySpec(unencryptedKey.array(), "AES"), new IvParameterSpec(iv));
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
}
