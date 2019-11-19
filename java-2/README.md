# Usage

Vault Java library is available in Maven Central:

pom.xml:
```
<dependency>
  <groupId>com.nitorcreations</groupId>
  <artifactId>aws-vault-2</artifactId>
  <version>0.15</version>
</dependency>
```

Setting up VaultClient:
```
VaultClient vaultClient = new VaultClient(bucketName, kmsKey, Region.EU_WEST_1);
```

Fetching data from the Vault:
```
String password = vaultClient.lookup("my-password-key");
```