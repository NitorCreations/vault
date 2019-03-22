package com.nitorcreations.vault;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class VaultClientTest {

  private static final String BUCKET_NAME_FIXTURE = "bucket";
  private static final String SECRET_NAME_FIXTURE = "foo";
  private static final String KEY_FIXTURE = "key";
  private static final String VAULT_KEY_FIXTURE = "vaultKey";
  private static final String DATA_FIXTURE = "data";

  private AmazonS3 s3Mock;
  private AWSKMS kmsMock;
  private VaultClient vaultClient;

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Test
  public void constructorThrowsIaeWhenS3Null() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(null, mock(AWSKMS.class), BUCKET_NAME_FIXTURE, VAULT_KEY_FIXTURE);
  }

  @Test
  public void constructorThrowsIaeWhenKmsNull() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(mock(AmazonS3.class), null, BUCKET_NAME_FIXTURE, VAULT_KEY_FIXTURE);
  }

  @Test
  public void constructorThrowsIaeWhenBucketNameNull() {
    expectedException.expect(IllegalArgumentException.class);
    new VaultClient(mock(AmazonS3.class), mock(AWSKMS.class), null, VAULT_KEY_FIXTURE);
  }

  @Before
  public void setUpS3() throws Exception {
    s3Mock = mock(AmazonS3.class);
    when(s3Mock.getObject(any(GetObjectRequest.class))).thenReturn(createS3Object("value"), createS3Object(KEY_FIXTURE));
  }

  @Before
  public void setUpObjectListing() {
    ObjectListing mockObjectListing = mock(ObjectListing.class);
    final S3ObjectSummary valueObjectSummary = new S3ObjectSummary();
    valueObjectSummary.setKey(SECRET_NAME_FIXTURE + ".encrypted");
    final S3ObjectSummary keyObjectSummary = new S3ObjectSummary();
    keyObjectSummary.setKey(SECRET_NAME_FIXTURE + ".key");
    when(mockObjectListing.getObjectSummaries()).thenReturn(asList(valueObjectSummary, keyObjectSummary));
    when(s3Mock.listObjects(BUCKET_NAME_FIXTURE)).thenReturn(mockObjectListing);
  }

  @Before
  public void setUpKms() {
    kmsMock = mock(AWSKMS.class);
    when(kmsMock.decrypt(any(DecryptRequest.class))).thenReturn(createDecryptResult());
    when(kmsMock.generateDataKey(any(GenerateDataKeyRequest.class))).thenReturn(createGenerateDataKeyResult());
  }

  @Before
  public void setUpVaultClient() {
    vaultClient = new VaultClient(s3Mock, kmsMock, BUCKET_NAME_FIXTURE, VAULT_KEY_FIXTURE);
  }

  private static DecryptResult createDecryptResult() {
    ByteBuffer byteBuffer = randomBuffer();
    return new DecryptResult().withPlaintext(byteBuffer);
  }

  private static S3Object createS3Object(final String content) throws IOException {
    final S3Object s3Object = new S3Object();
    s3Object.setObjectContent(IOUtils.toInputStream(content, "UTF-8"));
    return s3Object;
  }

  private static GenerateDataKeyResult createGenerateDataKeyResult() {
    return new GenerateDataKeyResult().withPlaintext(randomBuffer()).withCiphertextBlob(randomBuffer());
  }

  @Test
  public void lookupReadsEncryptedValueFromS3() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock).getObject(argThat(getObjectRequest -> (SECRET_NAME_FIXTURE + ".encrypted").equals(getObjectRequest.getKey())));
  }

  @Test
  public void lookupReadsKeyFromS3() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock).getObject(argThat(getObjectRequest -> (SECRET_NAME_FIXTURE + ".key").equals(getObjectRequest.getKey())));
  }

  @Test
  public void lookupUsesCorrectBucket() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(s3Mock, times(2)).getObject(argThat(getObjectRequest -> BUCKET_NAME_FIXTURE.equals(getObjectRequest.getBucketName())));
  }

  @Test
  public void lookupDecryptsSecretUsingKms() throws Exception {
    vaultClient.lookup(SECRET_NAME_FIXTURE);
    verify(kmsMock).decrypt(any());
  }

  @Test
  public void storeWritesEncryptedValueToS3() throws Exception {
    vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE);
    verify(s3Mock).putObject(argThat(putObjectRequest -> (SECRET_NAME_FIXTURE + ".encrypted").equals(putObjectRequest.getKey())));
  }

  @Test
  public void storeWritesEncryptionKeyToS3() throws Exception {
    vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE);
    verify(s3Mock).putObject(argThat(putObjectRequest -> (SECRET_NAME_FIXTURE + ".key").equals(putObjectRequest.getKey())));
  }

  @Test
  public void storeWritesKeyAndValueToCorrectBucket() throws Exception {
    vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE);
    verify(s3Mock, times(2)).putObject(argThat(putObjectRequest -> BUCKET_NAME_FIXTURE.equals(putObjectRequest.getBucketName())));
  }

  @Test
  public void storeEncryptsValueUsingTheCorrectVaultKey() throws Exception {
    vaultClient.store(SECRET_NAME_FIXTURE, DATA_FIXTURE);
    verify(kmsMock).generateDataKey(argThat(generateDataKeyRequest -> VAULT_KEY_FIXTURE.equals(generateDataKeyRequest.getKeyId())));
  }

  @Test
  public void existsReturnsCorrectResult() {
    final boolean expectedReturnValue = true;
    when(s3Mock.doesObjectExist(BUCKET_NAME_FIXTURE, SECRET_NAME_FIXTURE + ".key")).thenReturn(expectedReturnValue);
    assertThat(vaultClient.exists(SECRET_NAME_FIXTURE), is(expectedReturnValue));
  }

  @Test
  public void deleteRemovesKeyFromS3() {
    vaultClient.delete(SECRET_NAME_FIXTURE);
    verify(s3Mock).deleteObject(argThat(deleteObjectRequest -> (SECRET_NAME_FIXTURE + ".key").equals(deleteObjectRequest.getKey())));
  }

  @Test
  public void deleteRemovesEncryptedValueFromS3() {
    vaultClient.delete(SECRET_NAME_FIXTURE);
    verify(s3Mock).deleteObject(argThat(deleteObjectRequest -> (SECRET_NAME_FIXTURE + ".encrypted").equals(deleteObjectRequest.getKey())));
  }

  @Test
  public void deleteRemovesKeyAndValueFromCorrectBucket() {
    vaultClient.delete(SECRET_NAME_FIXTURE);
    verify(s3Mock, times(2)).deleteObject(argThat(deleteObjectRequest -> BUCKET_NAME_FIXTURE.equals(deleteObjectRequest.getBucketName())));
  }

  @Test
  public void allReturnsCorrectNumberOfNames() {
    assertThat(vaultClient.all().size(), is(1));
  }

  @Test
  public void allReturnsCorrectName() {
    assertThat(vaultClient.all().get(0), is(equalTo(SECRET_NAME_FIXTURE)));
  }

  private static ByteBuffer randomBuffer() {
    final byte[] bytes = new byte[16];
    new Random().nextBytes(bytes);
    return ByteBuffer.wrap(bytes);
  }
}
