# Usage

Vault Java library is available in Maven Central:

pom.xml:

```xml
<dependency>
  <groupId>com.nitorcreations</groupId>
  <artifactId>aws-vault</artifactId>
  <version>0.14</version>
</dependency>
```

Setting up VaultClient:

```java
String region = "eu-central-1";

AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
AWSKMS kmsClient = AWSKMSClientBuilder.standard()
        .withRegion(region)
        .build();

VaultClient vaultClient = new VaultClient(s3Client, kmsClient, bucketName, kmsKey);
```

Fetching data from the Vault:

```java
String password = vaultClient.lookup("my-password-key");
```
