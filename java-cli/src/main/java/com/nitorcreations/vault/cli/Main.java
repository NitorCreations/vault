package com.nitorcreations.vault.cli;

import com.nitorcreations.vault2.VaultClient;
import com.nitorcreations.vault2.VaultException;
import com.nitorcreations.vault2.VaultClient.KeyAndBucket;

import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.concurrent.Callable;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;
import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;
import static picocli.CommandLine.ArgGroup;

import picocli.CommandLine;
import picocli.CommandLine.Help.Ansi;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;

import static java.nio.charset.StandardCharsets.UTF_8;

@Command(name="vault", mixinStandardHelpOptions = true, version = "AWS-Vault 0.15")
public class Main implements Callable<Integer> {
    @ArgGroup(exclusive = true, multiplicity="1")
    Command command;
    @Option(names = {"-w", "--overwrite"}, description="Add this argument if you want to overwrite an existing element")
    boolean overwrite;
    @Option(names = {"-v", "--value"}, description="Value to store")
    String value;
    @Option(names = {"-f", "--file"}, description="File to store. If no -s argument given, the name of the file is used as the default name. Give - for stdin")
    File file;
    @Option(names = {"-o", "--outfile"}, description="The file to write the data to")
    File output;
    @Option(names = {"-p", "--prefix"}, description="Optional prefix to store value under. empty by default")
    String prefix = "";
    @Option(names = {"--vaultstack"}, description="Optional CloudFormation stack to lookup key and bucket. \"vault\" by default")
    String vaultStack = "vault";
    @Option(names = {"-b", "--bucket"}, description="Override the bucket name either for initialization or storing and looking up values")
    String bucket;
    @Option(names = {"-k", "--key-arn"}, description="Override the KMS key arn for storinig or looking up")
    String keyArn;
    @Option(names = {"--id"}, description="Give an IAM access key id to override those defined by environent")
    String id;
    @Option(names = {"--secret"}, description="Give an IAM secret access key to override those defined by environent")
    String secret;
    @Option(names = {"-r", "--region"}, description="Give a region for the stack and bucket")
    Region region;

    public static void main(String[] args) {
      String logConfig = ".level=" + java.util.logging.Level.INFO + '\n';
      logConfig += "handlers=java.util.logging.ConsoleHandler\n";
      // ensure ConsoleHandler does not filter
      logConfig += "java.util.logging.ConsoleHandler" + ".level=" + java.util.logging.Level.FINEST + '\n';

      //set your custom levels
      logConfig += "com.amazonaws.auth.profile.internal.BasicProfileConfigLoader.level=" + java.util.logging.Level.SEVERE + "\n";

      try {
        java.util.logging.LogManager.getLogManager().readConfiguration(new java.io.ByteArrayInputStream(logConfig.getBytes("UTF-8")));
        // no need to close ByteArrayInputStream -- it is a no-op
      }
      catch (IOException ioe) {
        System.err.println("cannot fully configure logging");
        ioe.printStackTrace();
      }
      System.exit(new CommandLine(new Main()).execute(args));
    }

    @Override
    public Integer call() {
      if (region == null && System.getenv("AWS_DEFAULT_REGION") == null) {
        region = new DefaultAwsRegionProviderChain().getRegion();
      }
      if (prefix == null && System.getenv("VAULT_PREFIX") != null) {
        prefix = System.getenv("VAULT_PREFIX");
      }
      if (bucket == null && System.getenv("VAULT_BUCKET") != null) {
        bucket = System.getenv("VAULT_BUCKET");
      }
      if (keyArn == null && System.getenv("VAULT_KEY")  != null) {
        keyArn = System.getenv("VAULT_KEY");
      }
      if (bucket == null || keyArn == null) {
        KeyAndBucket kb = VaultClient.resolveKeyAndBucket(vaultStack, region);
        if (bucket == null) {
          bucket = kb.vaultBucket;
        }
        if (keyArn == null) {
          keyArn = kb.keyArn;
        }
      }

      AwsCredentialsProvider provider = DefaultCredentialsProvider.create();
      if (id != null && secret != null) {
        AwsCredentials creds = AwsBasicCredentials.create(id, secret);
        provider = StaticCredentialsProvider.create(creds);
      }

      S3ClientBuilder s3ClientBuilder = S3Client.builder().credentialsProvider(provider);
      KmsClientBuilder kmsClientBuilder = KmsClient.builder().credentialsProvider(provider);

      if (region != null) {
        s3ClientBuilder.region(region);
        kmsClientBuilder.region(region);
      }

      VaultClient client = new VaultClient(s3ClientBuilder.build(), kmsClientBuilder.build(), bucket, keyArn);

      if (command.all) {
        for (String entry : client.all()) {
          System.out.println(entry);
        }
      } else if (command.lookup != null) {
        OutputStream out = null;
        try {
          if (output != null) {
            out = new FileOutputStream(output);
          } else {
            out = System.out;
          }
          out.write(client.lookupBytes(command.lookup));
        } catch (IOException ieo) {
          return 1;
        } catch (VaultException ve) {
          System.err.println("Failed to lookup \'" + command.lookup + "\': " + ve.getMessage());
          return 1;
        } finally {
          if (out != null) {
            try {
              out.close();
            } catch (Throwable e) {}
          }
        }
      } else if (command.store != null) {
        String storeName = command.store;
        if (command.store.isEmpty()) {
          if (file == null) {
            System.err.println("store needs either a name or file");
            CommandLine.usage(new Main(), System.err, Ansi.ON);
            return 1;
          } else {
            storeName = file.getName();
          }
        }
        try {
          byte[] data;
          if (file != null) {
            data = Files.readAllBytes(file.toPath());
          } else {
            data = value.getBytes(UTF_8);
          }
          client.store(storeName, data);
        } catch (IOException | VaultException e) {
          System.err.println("Failed to store " + storeName);
          return 1;
        }
      } else if (command.encrypt != null) {
        OutputStream out = null;
        try {
          if (output != null) {
            out = new FileOutputStream(output);
          } else {
            out = System.out;
          }
          byte[] data = null;
          if (command.encrypt.isEmpty()) {
            if (file == null) {
              System.err.println("encrypt needs either a value or file");
              CommandLine.usage(new Main(), System.err, Ansi.ON);
              return 1;
            } else {
              data = Files.readAllBytes(file.toPath());
            }
          } else {
            data = command.encrypt.getBytes(UTF_8);
          }
          out.write(getEncoder().encode(client.directEncrypt(data)));
        } catch (IOException ieo) {
          return 1;
        } finally {
          if (out != null) {
            try {
              out.close();
            } catch (Throwable e) {}
          }
        } 
      } else if (command.decrypt != null) {
        OutputStream out = null;
        try {
          if (output != null) {
            out = new FileOutputStream(output);
          } else {
            out = System.out;
          }
          byte[] data = null;
          if (command.decrypt.isEmpty()) {
            if (file == null) {
              System.err.println("decrypt needs either a value or a file");
              CommandLine.usage(new Main(), System.err, Ansi.ON);
              return 1;
            } else {
              data = Files.readAllBytes(file.toPath());
            }
          } else {
            data = getDecoder().decode(command.decrypt);
          }
          out.write(client.directDecrypt(data));
        } catch (IOException ieo) {
          return 1;
        } finally {
          if (out != null) {
            try {
              out.close();
            } catch (Throwable e) {}
          }
        } 
      } else if (command.delete != null && !command.delete.isEmpty()) {
        try {
          client.delete(command.delete);
        } catch (VaultException e) {
          System.err.println("Failed to delete " + command.delete);
          return 1;
        }
      }
      return 0;
    }

    static class Command {
        @Option(names = {"-s", "--store"}, arity = "0..1",
                description="Name of element to store. Optionally read from file name")
        String store;
        @Option(names = {"-l", "--lookup"},
                description="Name of element to lookup")
        String lookup;
        @Option(names = {"-d", "--delete"},
                description="Name of element to delete")
        String delete;
        @Option(names = {"-a", "--all"},
                description="List available secrets")
        boolean all;
        @Option(names = {"-e", "--encrypt"}, arity = "0..1",
                description="Directly encrypt given value")
        String encrypt;
        @Option(names = {"-y", "--decrypt"}, arity = "0..1",
                description="Directly decrypt given value")
        String decrypt;
    }
}