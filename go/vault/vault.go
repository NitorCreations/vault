package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net/http"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

func Init() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	s3Client := s3.NewFromConfig(cfg)
	output, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String("jounin-testi-bucksu-666"),
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("first page results:")
	for _, object := range output.Contents {
		fmt.Printf("%s\n", aws.ToString(object.Key))
	}
}

func LoadVault() (Vault, error) {
	res := Vault{}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return res, fmt.Errorf("error creating config: %v", err)
	}
	cfnParams, err := getCloudformationParams(&cfg, "vault")
	if err != nil {
		return res, err
	}
	res.cloudformationParams = cfnParams
	res.s3Client = *s3.NewFromConfig(cfg)
	res.kmsClient = *kms.NewFromConfig(cfg)

	return res, nil
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
	res := []string{}

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
	var res []byte
	dataKey, err := v.s3Client.GetObject(context.TODO(), &s3.GetObjectInput{Bucket: &v.cloudformationParams.BucketName, Key: &key})
	if err != nil {
		return res, err
	}
	defer dataKey.Body.Close()
	res, err = io.ReadAll(dataKey.Body)
	if err != nil {
		return res, err
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
	_, err := v.s3Client.HeadObject(context.TODO(), &s3.HeadObjectInput{Bucket: &v.cloudformationParams.BucketName, Key: &keyName})
	if err != nil {
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) && responseError.ResponseError.HTTPStatusCode() == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
func (v Vault) putS3Object(key string, value io.Reader, c chan error) {
	_, err := v.s3Client.PutObject(context.TODO(), &s3.PutObjectInput{Bucket: &v.cloudformationParams.BucketName, Key: &key, Body: value})
	if err != nil {
		c <- err
		return
	}
	c <- nil
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
