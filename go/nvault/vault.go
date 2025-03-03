package nvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	types2 "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type Vault struct {
	s3Client             s3.Client
	cloudformationParams CloudFormationParams
	kmsClient            kms.Client
}

type CloudFormationParams struct {
	BucketName string
	KeyArn     string
}

type Meta struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
}

type EncryptedObject struct {
	DataKey       []byte
	EncryptedBlob []byte
	Meta          string
}

// LoadVault stackNameOpt is made an optional string array,
// so that one can call LoadVault with no params or first parameter being vault stack name,
// i.e. vault.LoadVault() === vault.LoadVault("vault")
func LoadVault(stackNameOpt ...string) (Vault, error) {
	res := Vault{}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return res, fmt.Errorf("error creating config: %v", err)
	}
	// fetch VAULT_STACK from env
	stackName := os.Getenv("VAULT_STACK")

	if len(stackNameOpt) != 0 && stackNameOpt[0] != "" {
		stackName = stackNameOpt[0]
	} else if stackName == "" {
		stackName = "vault"
	}
	cfnParams, err := getCloudformationParams(&cfg, stackName)
	if err != nil {
		return res, err
	}
	res.cloudformationParams = cfnParams
	res.s3Client = *s3.NewFromConfig(cfg)
	res.kmsClient = *kms.NewFromConfig(cfg)

	return res, nil
}

func FromCloudFormationParams(params CloudFormationParams) (*Vault, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("error creating config: %v", err)
	}
	return &Vault{
		cloudformationParams: params,
		s3Client:             *s3.NewFromConfig(cfg),
		kmsClient:            *kms.NewFromConfig(cfg),
	}, nil
}

func getCloudformationParams(cfg *aws.Config, stackName string) (CloudFormationParams, error) {
	res := CloudFormationParams{}
	cfnClient := cloudformation.NewFromConfig(*cfg)
	describeStack, err := cfnClient.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{
		StackName: &stackName,
	})
	if err != nil {
		return res, err
	}
	if len(describeStack.Stacks) == 0 {
		return res, fmt.Errorf("no stack found called %s", stackName)
	} else if len(describeStack.Stacks) > 1 {
		return res, fmt.Errorf("should only find one stack for vault, but found %d", len(describeStack.Stacks))
	}
	stackOutputs := describeStack.Stacks[0].Outputs
	for _, output := range stackOutputs {
		if *output.OutputKey == "vaultBucketName" {
			res.BucketName = *output.OutputValue
		} else if *output.OutputKey == "kmsKeyArn" {
			res.KeyArn = *output.OutputValue
		}
	}
	if res.BucketName == "" {
		return res, fmt.Errorf("bucket name not found for %s, required", stackName)
	}
	return res, nil
}

func (v Vault) All() ([]string, error) {
	var res []string

	output, err := v.s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(v.cloudformationParams.BucketName),
	})
	if err != nil {
		return res, err
	}
	for _, secret := range output.Contents {
		key, found := strings.CutSuffix(*secret.Key, ".aesgcm.encrypted")
		if found {
			res = append(res, key)
		}
	}
	return res, nil
}

func (v Vault) getS3Object(key string) ([]byte, error) {
	dataKey, err := v.s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket:       &v.cloudformationParams.BucketName,
		Key:          &key,
		ChecksumMode: types2.ChecksumModeEnabled,
	})
	if err != nil {
		return nil, err
	}
	defer dataKey.Body.Close()

	res, err := io.ReadAll(dataKey.Body)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (v Vault) Lookup(key string) (string, error) {
	res := ""
	dataKeyBlob, err := v.getS3Object(fmt.Sprintf("%s.key", key))
	if err != nil {
		return res, err
	}
	cipherTextBlob, err := v.getS3Object(fmt.Sprintf("%s.aesgcm.encrypted", key))
	if err != nil {
		return res, err
	}

	metaAddBlob, err := v.getS3Object(fmt.Sprintf("%s.meta", key))
	if err != nil {
		return res, err
	}
	var meta Meta
	err = json.Unmarshal(metaAddBlob, &meta)
	if err != nil {
		return res, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(meta.Nonce)
	if err != nil {
		return res, err
	}
	cipherkeyDecrypt, err := v.kmsClient.Decrypt(context.TODO(), &kms.DecryptInput{
		CiphertextBlob: dataKeyBlob,
		KeyId:          &v.cloudformationParams.KeyArn,
	})
	if err != nil {
		return res, err
	}
	block, err := aes.NewCipher(cipherkeyDecrypt.Plaintext)
	if err != nil {
		return res, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return res, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, cipherTextBlob, metaAddBlob)
	if err != nil {
		return res, err
	}
	return string(plaintext), nil
}

func (v Vault) Exists(key string) (bool, error) {
	keyName := fmt.Sprintf("%s.key", key)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := v.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &v.cloudformationParams.BucketName,
		Key:    &keyName,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NotFound" {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (v Vault) putS3Object(key string, value io.Reader, c chan error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := v.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &v.cloudformationParams.BucketName,
		Key:    &key,
		Body:   value,
	})
	c <- err
}

func (v Vault) deleteS3Object(key string, c chan error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := v.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &v.cloudformationParams.BucketName,
		Key:    &key,
	})
	c <- err
}

func (v Vault) Delete(key string) error {
	exists, err := v.Exists(key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("key %s doesn't exists, cannot delete", key)
	}
	// is this how you do concurrency?
	ch := make(chan error)
	go v.deleteS3Object(fmt.Sprintf("%s.key", key), ch)
	go v.deleteS3Object(fmt.Sprintf("%s.aesgcm.encrypted", key), ch)
	go v.deleteS3Object(fmt.Sprintf("%s.meta", key), ch)
	recvd := 0
	for err := range ch {
		recvd += 1
		if err != nil {
			close(ch)
			return err
		}
		if recvd == 3 {
			close(ch)
		}
	}

	return nil
}

func (v Vault) Store(key string, value []byte) error {
	encrypted, err := v.encrypt(value)
	if err != nil {
		return err
	}
	// is this how you do concurrency?
	ch := make(chan error)
	go v.putS3Object(fmt.Sprintf("%s.key", key), bytes.NewReader(encrypted.DataKey), ch)
	go v.putS3Object(fmt.Sprintf("%s.aesgcm.encrypted", key), bytes.NewReader(encrypted.EncryptedBlob), ch)
	go v.putS3Object(fmt.Sprintf("%s.meta", key), strings.NewReader(encrypted.Meta), ch)
	recvd := 0
	for err := range ch {
		recvd += 1
		if err != nil {
			close(ch)
			return err
		}
		if recvd == 3 {
			close(ch)
		}
	}

	return nil
}

func (v Vault) encrypt(data []byte) (EncryptedObject, error) {
	res := EncryptedObject{}
	keyDict, err := v.kmsClient.GenerateDataKey(context.TODO(), &kms.GenerateDataKeyInput{KeyId: &v.cloudformationParams.KeyArn, KeySpec: types.DataKeySpecAes256})
	if err != nil {
		return res, err
	}
	res.DataKey = keyDict.CiphertextBlob
	block, err := aes.NewCipher(keyDict.Plaintext)
	if err != nil {
		return res, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return res, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	metaBytes, err := json.Marshal(Meta{Alg: "AESGCM", Nonce: base64.RawStdEncoding.EncodeToString(nonce)})
	if err != nil {
		return res, err
	}
	res.EncryptedBlob = aesgcm.Seal(nil, nonce, data, metaBytes)
	res.Meta = string(metaBytes)

	return res, nil
}
