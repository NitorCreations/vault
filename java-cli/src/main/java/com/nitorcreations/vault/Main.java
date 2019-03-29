package com.nitorcreations.vault;

import java.io.File;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import static picocli.CommandLine.Command;
import static picocli.CommandLine.Option;
import static picocli.CommandLine.ArgGroup;
import picocli.CommandLine;

@Command(name="vault", mixinStandardHelpOptions = true, version = "AWS-Vault 0.15")
public class Main implements Runnable {
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
    String region;

    public static void main(String[] args) {
        CommandLine.run(new Main(), args);
    }

    @Override
    public void run() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.print(gson.toJson(this));
    }

    static class Command {
        @Option(names = {"-s", "--store"},
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
        @Option(names = {"-e", "--encrypt"},
                description="Directly encrypt given value")
        String encrypt;
        @Option(names = {"-y", "--decrypt"},
                description="Directly decrypt given value")
        String decrypt;
    }
}