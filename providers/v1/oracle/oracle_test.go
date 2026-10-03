/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oracle

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	fakeoracle "github.com/external-secrets/external-secrets/providers/v1/oracle/fake"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	testingfake "github.com/external-secrets/external-secrets/runtime/testing/fake"
)

const (
	vaultOCID  = "vault-OCID"
	region     = "some-region"
	tenant     = "a-tenant"
	userOCID   = "user-OCID"
	secretKey  = "key"
	secretName = "name"
)

type vaultTestCase struct {
	mockClient     *fakeoracle.OracleMockClient
	apiInput       *secrets.GetSecretBundleByNameRequest
	apiOutput      *secrets.GetSecretBundleByNameResponse
	ref            *esv1.ExternalSecretDataRemoteRef
	apiErr         error
	expectError    string
	expectedSecret string
	// for testing secretmap
	expectedData map[string][]byte
}

func makeValidVaultTestCase() *vaultTestCase {
	smtc := vaultTestCase{
		mockClient:     &fakeoracle.OracleMockClient{},
		apiInput:       makeValidAPIInput(),
		ref:            makeValidRef(),
		apiOutput:      makeValidAPIOutput(),
		apiErr:         nil,
		expectError:    "",
		expectedSecret: "",
		expectedData:   map[string][]byte{},
	}
	smtc.mockClient.WithValue(*smtc.apiInput, *smtc.apiOutput, smtc.apiErr)
	return &smtc
}

func makeValidRef() *esv1.ExternalSecretDataRemoteRef {
	return &esv1.ExternalSecretDataRemoteRef{
		Key:     "test-secret",
		Version: "default",
	}
}

func makeValidAPIInput() *secrets.GetSecretBundleByNameRequest {
	return &secrets.GetSecretBundleByNameRequest{
		SecretName: new("test-secret"),
		VaultId:    new("test-vault"),
	}
}

func makeValidAPIOutput() *secrets.GetSecretBundleByNameResponse {
	return &secrets.GetSecretBundleByNameResponse{
		SecretBundle: secrets.SecretBundle{},
	}
}

func makeValidVaultTestCaseCustom(tweaks ...func(smtc *vaultTestCase)) *vaultTestCase {
	smtc := makeValidVaultTestCase()
	for _, fn := range tweaks {
		fn(smtc)
	}
	smtc.mockClient.WithValue(*smtc.apiInput, *smtc.apiOutput, smtc.apiErr)
	return smtc
}

// This case can be shared by both GetSecret and GetSecretMap tests.
// bad case: set apiErr.
var setAPIErr = func(smtc *vaultTestCase) {
	smtc.apiErr = errors.New("oh no")
	smtc.expectError = "oh no"
}

var setNilMockClient = func(smtc *vaultTestCase) {
	smtc.mockClient = nil
	smtc.expectError = errUninitalizedOracleProvider
}

func TestIsNil(t *testing.T) {
	tbl := []struct {
		name string
		val  any
		exp  bool
	}{
		{
			name: "oracle vault",
			val:  vault.VaultsClient{},
			exp:  false,
		},
	}

	for _, row := range tbl {
		t.Run(row.name, func(t *testing.T) {
			res := esutils.IsNil(row.val)
			if res != row.exp {
				t.Errorf("IsNil(%#v)=%t, expected %t", row.val, res, row.exp)
			}
		})
	}
}

func TestOracleVaultGetSecret(t *testing.T) {
	secretValue := "changedvalue"
	// good case: default version is set
	// key is passed in, output is sent back
	setSecretString := func(smtc *vaultTestCase) {
		smtc.apiOutput = &secrets.GetSecretBundleByNameResponse{
			SecretBundle: secrets.SecretBundle{
				SecretId:      new("test-id"),
				VersionNumber: new(int64(1)),
				SecretBundleContent: secrets.Base64SecretBundleContentDetails{
					Content: new(base64.StdEncoding.EncodeToString([]byte(secretValue))),
				},
			},
		}
		smtc.expectedSecret = secretValue
	}

	successCases := []*vaultTestCase{
		makeValidVaultTestCaseCustom(setAPIErr),
		makeValidVaultTestCaseCustom(setNilMockClient),
		makeValidVaultTestCaseCustom(setSecretString),
	}

	sm := VaultManagementService{}
	for k, v := range successCases {
		sm.Client = v.mockClient
		out, err := sm.GetSecret(context.Background(), *v.ref)
		if !ErrorContains(err, v.expectError) {
			t.Errorf("[%d] unexpected error: %s, expected: '%s'", k, err.Error(), v.expectError)
		}
		if string(out) != v.expectedSecret {
			t.Errorf("[%d] unexpected secret: expected %s, got %s", k, v.expectedSecret, string(out))
		}
	}
}

func TestGetSecretMap(t *testing.T) {
	// good case: default version & deserialization
	setDeserialization := func(smtc *vaultTestCase) {
		smtc.apiOutput.SecretBundleContent = secrets.Base64SecretBundleContentDetails{
			Content: new(base64.StdEncoding.EncodeToString([]byte(`{"foo":"bar"}`))),
		}
		smtc.expectedData["foo"] = []byte("bar")
	}

	// bad case: invalid json
	setInvalidJSON := func(smtc *vaultTestCase) {
		smtc.apiOutput.SecretBundleContent = secrets.Base64SecretBundleContentDetails{
			Content: new(base64.StdEncoding.EncodeToString([]byte(`-----------------`))),
		}
		smtc.expectError = "unable to unmarshal secret"
	}

	successCases := []*vaultTestCase{
		makeValidVaultTestCaseCustom(setDeserialization),
		makeValidVaultTestCaseCustom(setInvalidJSON),
		makeValidVaultTestCaseCustom(setNilMockClient),
		makeValidVaultTestCaseCustom(setAPIErr),
	}

	sm := VaultManagementService{}
	for k, v := range successCases {
		sm.Client = v.mockClient
		out, err := sm.GetSecretMap(context.Background(), *v.ref)
		if !ErrorContains(err, v.expectError) {
			t.Errorf("[%d] unexpected error: %s, expected: '%s'", k, err.Error(), v.expectError)
		}
		if err == nil && !reflect.DeepEqual(out, v.expectedData) {
			t.Errorf("[%d] unexpected secret data: expected %#v, got %#v", k, v.expectedData, out)
		}
	}
}

func ErrorContains(out error, want string) bool {
	if out == nil {
		return want == ""
	}
	if want == "" {
		return false
	}
	return strings.Contains(out.Error(), want)
}

type storeModifier func(*esv1.SecretStore) *esv1.SecretStore

func makeSecretStore(vault, region string, fn ...storeModifier) *esv1.SecretStore {
	store := &esv1.SecretStore{
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{
				Oracle: &esv1.OracleProvider{
					Vault:  vault,
					Region: region,
				},
			},
		},
	}

	for _, f := range fn {
		store = f(store)
	}
	return store
}
func withSecretAuth(user, tenancy string) storeModifier {
	return func(store *esv1.SecretStore) *esv1.SecretStore {
		store.Spec.Provider.Oracle.Auth = &esv1.OracleAuth{
			User:    user,
			Tenancy: tenancy,
		}
		return store
	}
}
func withPrivateKey(name, key string, namespace *string) storeModifier {
	return func(store *esv1.SecretStore) *esv1.SecretStore {
		store.Spec.Provider.Oracle.Auth.SecretRef.PrivateKey = esmeta.SecretKeySelector{
			Name:      name,
			Key:       key,
			Namespace: namespace,
		}
		return store
	}
}
func withFingerprint(name, key string, namespace *string) storeModifier {
	return func(store *esv1.SecretStore) *esv1.SecretStore {
		store.Spec.Provider.Oracle.Auth.SecretRef.Fingerprint = esmeta.SecretKeySelector{
			Name:      name,
			Key:       key,
			Namespace: namespace,
		}
		return store
	}
}

type ValidateStoreTestCase struct {
	store *esv1.SecretStore
	err   error
}

func TestValidateStore(t *testing.T) {
	namespace := "my-namespace"
	testCases := []ValidateStoreTestCase{
		{
			store: makeSecretStore("", region),
			err:   errors.New("vault cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, ""),
			err:   errors.New("region cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth("", tenant)),
			err:   errors.New("user cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, "")),
			err:   errors.New("tenant cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey("", secretKey, nil)),
			err:   errors.New("privateKey.name cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey(secretName, secretKey, &namespace)),
			err:   errors.New("namespace should either be empty or match the namespace of the SecretStore for a namespaced SecretStore"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey(secretName, "", nil)),
			err:   errors.New("privateKey.key cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey(secretName, secretKey, nil), withFingerprint("", secretKey, nil)),
			err:   errors.New("fingerprint.name cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey(secretName, secretKey, nil), withFingerprint(secretName, secretKey, &namespace)),
			err:   errors.New("namespace should either be empty or match the namespace of the SecretStore for a namespaced SecretStore"),
		},
		{
			store: makeSecretStore(vaultOCID, region, withSecretAuth(userOCID, tenant), withPrivateKey(secretName, secretKey, nil), withFingerprint(secretName, "", nil)),
			err:   errors.New("fingerprint.key cannot be empty"),
		},
		{
			store: makeSecretStore(vaultOCID, region),
			err:   nil,
		},
	}
	p := VaultManagementService{}
	for _, tc := range testCases {
		_, err := p.ValidateStore(tc.store)
		if tc.err != nil && err != nil && err.Error() != tc.err.Error() {
			t.Errorf("test failed! want %v, got %v", tc.err, err)
		} else if tc.err == nil && err != nil {
			t.Errorf("want nil got err %v", err)
		} else if tc.err != nil && err == nil {
			t.Errorf("want err %v got nil", tc.err)
		}
	}
}

func TestVaultManagementServiceNewClient(t *testing.T) {
	t.Parallel()

	namespace := "default"
	authSecretName := "oracle-auth"

	auth := &esv1.OracleAuth{
		User:    "user",
		Tenancy: "tenancy",
		SecretRef: esv1.OracleSecretRef{
			PrivateKey: esmeta.SecretKeySelector{
				Name: authSecretName,
				Key:  "privateKey",
			},
			Fingerprint: esmeta.SecretKeySelector{
				Name: authSecretName,
				Key:  "fingerprint",
			},
		},
	}

	tests := []struct {
		desc        string
		secretStore *esv1.SecretStore
		expectedErr string
	}{
		{
			desc: "no retry settings",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth:   auth,
						},
					},
				},
			},
		},
		{
			desc: "fill all the retry settings",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth:   auth,
						},
					},
					RetrySettings: &esv1.SecretStoreRetrySettings{
						RetryInterval: new("1s"),
						MaxRetries:    new(int32(5)),
					},
				},
			},
		},
		{
			desc: "partially configure the retry settings - retry interval",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth:   auth,
						},
					},
					RetrySettings: &esv1.SecretStoreRetrySettings{
						RetryInterval: new("1s"),
					},
				},
			},
		},
		{
			desc: "partially configure the retry settings - max retries",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth:   auth,
						},
					},
					RetrySettings: &esv1.SecretStoreRetrySettings{
						MaxRetries: new(int32(5)),
					},
				},
			},
		},
		{
			desc: "auth secret does not exist",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth: &esv1.OracleAuth{
								User:    "user",
								Tenancy: "tenancy",
								SecretRef: esv1.OracleSecretRef{
									PrivateKey: esmeta.SecretKeySelector{
										Name: "non-existing-secret",
										Key:  "privateKey",
									},
									Fingerprint: esmeta.SecretKeySelector{
										Name: "non-existing-secret",
										Key:  "fingerprint",
									},
								},
							},
						},
					},
					RetrySettings: &esv1.SecretStoreRetrySettings{
						RetryInterval: new("invalid"),
					},
				},
			},
			expectedErr: `cannot get Kubernetes secret "non-existing-secret" from namespace "default": secrets "non-existing-secret" not found`,
		},
		{
			desc: "invalid retry interval",
			secretStore: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						Oracle: &esv1.OracleProvider{
							Vault:  vaultOCID,
							Region: region,
							Auth:   auth,
						},
					},
					RetrySettings: &esv1.SecretStoreRetrySettings{
						RetryInterval: new("invalid"),
					},
				},
			},
			expectedErr: "cannot setup new oracle client: time: invalid duration",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			provider := &VaultManagementService{
				Client:         &fakeoracle.OracleMockClient{},
				KmsVaultClient: nil,
				vault:          vaultOCID,
			}

			pk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to create a private key: %v", err)
			}
			schema := runtime.NewScheme()
			if err := corev1.AddToScheme(schema); err != nil {
				t.Fatalf("failed to add to schema: %v", err)
			}
			builder := clientfake.NewClientBuilder().WithRuntimeObjects(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      authSecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"privateKey": pem.EncodeToMemory(&pem.Block{
						Type:  "RSA PRIVATE KEY",
						Bytes: x509.MarshalPKCS1PrivateKey(pk),
					}),
					"fingerprint": []byte("fingerprint"),
				},
			})

			_, err = provider.NewClient(context.Background(), tc.secretStore, builder.Build(), namespace)
			if err != nil {
				if tc.expectedErr == "" {
					t.Fatalf("failed to call NewClient: %v", err)
				}

				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("received an unexpected error: %q should have contained %q", err.Error(), tc.expectedErr)
				}
				return
			}

			if tc.expectedErr != "" {
				t.Fatalf("expeceted to receive an error but got nil")
			}
		})
	}
}

func TestOracleVaultGetAllSecrets(t *testing.T) {
	var testCases = map[string]struct {
		vms    *VaultManagementService
		ref    esv1.ExternalSecretFind
		result map[string][]byte
	}{
		"filters secrets that don't match the pattern": {
			&VaultManagementService{
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s2id: s2bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{
					SecretSummaries: []vault.SecretSummary{
						s1summary,
						s2summary,
					},
				},
			},
			esv1.ExternalSecretFind{
				Name: &esv1.FindName{
					RegExp: "^test.*",
				},
			},
			map[string][]byte{
				s1id: []byte(s1id),
			},
		},
		"filters secrets that are deleting": {
			&VaultManagementService{
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s2id: s2bundle,
						s3id: s3bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{
					SecretSummaries: []vault.SecretSummary{
						s1summary,
						s2summary,
						s3summary,
					},
				},
			},
			esv1.ExternalSecretFind{
				Name: &esv1.FindName{
					RegExp: ".*",
				},
			},
			map[string][]byte{
				s1id: []byte(s1id),
				s2id: []byte(s2id),
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			result, err := testCase.vms.GetAllSecrets(context.Background(), testCase.ref)
			assert.NoError(t, err)
			assert.EqualValues(t, testCase.result, result)
		})
	}
}

func TestOracleVaultPushSecret(t *testing.T) {
	testSecretKey := "test-secret-key"
	encryptionKey := "must-not-be-blank-for-push"
	var testCases = map[string]struct {
		vms       *VaultManagementService
		data      testingfake.PushSecretData
		validator func(service *VaultManagementService) bool
		content   string
	}{
		"create a secret if not exists": {
			&VaultManagementService{
				encryptionKey: encryptionKey,
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s2id: s2bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			testingfake.PushSecretData{
				SecretKey: testSecretKey,
				RemoteKey: s1id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).CreatedCount == 1
			},
			"created",
		},
		"create a json secret if not exists": {
			&VaultManagementService{
				encryptionKey: encryptionKey,
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s2id: s2bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			testingfake.PushSecretData{
				SecretKey: testSecretKey,
				RemoteKey: s1id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).CreatedCount == 1
			},
			"{'key-a':'secret-a', 'key-b': 'secret-b'}",
		},
		"update a secret if exists": {
			&VaultManagementService{
				encryptionKey: encryptionKey,
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s2id: s2bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			testingfake.PushSecretData{
				SecretKey: testSecretKey,
				RemoteKey: s1id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).UpdatedCount == 1
			},
			"updated",
		},
		"neither create nor update if secret content is unchanged": {
			&VaultManagementService{
				encryptionKey: encryptionKey,
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s2id: s2bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			testingfake.PushSecretData{
				SecretKey: testSecretKey,
				RemoteKey: s1id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).UpdatedCount == 0 &&
					vms.VaultClient.(*fakeoracle.OracleMockVaultClient).CreatedCount == 0
			},
			s1id,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			s := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte(testCase.content)}}
			err := testCase.vms.PushSecret(context.Background(), s, testCase.data)
			assert.NoError(t, err)
			assert.True(t, testCase.validator(testCase.vms))
		})
	}
}

func TestPushSecretReusesPendingDeletionName(t *testing.T) {
	const (
		testSecretKey = "test-secret-key"
		encryptionKey = "must-not-be-blank-for-push"
		secretOCID    = "ocid1.vaultsecret.oc1..pending"
		compartment   = "ocid1.compartment.oc1..example"
		vaultID       = "ocid1.vault.oc1..example"
	)
	deletionTime := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	remote := testingfake.PushSecretData{
		SecretKey: testSecretKey,
		RemoteKey: s1id,
	}
	nameTaken := &fakeoracle.ServiceError{
		Code:    400,
		OCICode: "InvalidParameter",
		Message: "name already exists",
	}

	pending := makeSecretSummary(s1id, true)
	pending.Id = new(secretOCID)
	pending.LifecycleState = vault.SecretSummaryLifecycleStatePendingDeletion
	pending.TimeOfDeletion = &common.SDKTime{Time: deletionTime}

	creating := pending
	creating.LifecycleState = vault.SecretSummaryLifecycleStateCreating
	creating.TimeOfDeletion = nil

	active := pending
	active.LifecycleState = vault.SecretSummaryLifecycleStateActive
	active.TimeOfDeletion = nil

	t.Run("cancels pending deletion and updates once the bundle is readable", func(t *testing.T) {
		client := &fakeoracle.OracleMockClient{
			SecretBundles: map[string]secrets.SecretBundle{},
		}
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{pending},
			CreateErr:       nameTaken,
			OnCancel: func() {
				bundle := makeSecretBundle(s1id, false)
				bundle.SecretId = new(secretOCID)
				client.SecretBundles[s1id] = bundle
			},
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client:        client,
			VaultClient:   vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.NoError(t, err)
		assert.Equal(t, 1, vaultClient.CreatedCount)
		assert.Equal(t, 1, vaultClient.CancelledCount)
		assert.Equal(t, secretOCID, vaultClient.LastCancelledSecretID)
		assert.Equal(t, 1, vaultClient.UpdatedCount)
		assert.Equal(t, secretOCID, vaultClient.LastUpdatedSecretID)
		if assert.NotNil(t, vaultClient.LastListRequest.Name) {
			assert.Equal(t, s1id, *vaultClient.LastListRequest.Name)
		}
		if assert.NotNil(t, vaultClient.LastListRequest.CompartmentId) {
			assert.Equal(t, compartment, *vaultClient.LastListRequest.CompartmentId)
		}
	})

	t.Run("reports the reservation time when the secret stays unreadable after cancel", func(t *testing.T) {
		client := &fakeoracle.OracleMockClient{
			SecretBundles: map[string]secrets.SecretBundle{},
		}
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{pending},
			CreateErr:       nameTaken,
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client:        client,
			VaultClient:   vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.EqualError(t, err, "oci vault secret \"test1\" is pending deletion until 2026-10-04T12:00:00Z; scheduled deletion was canceled and the secret will be updated once it is active")
		assert.Equal(t, 1, vaultClient.CancelledCount)
		assert.Equal(t, 0, vaultClient.UpdatedCount)

		// The next reconcile sees the secret once OCI finishes canceling deletion.
		bundle := makeSecretBundle(s1id, false)
		bundle.SecretId = new(secretOCID)
		client.SecretBundles[s1id] = bundle
		err = vms.PushSecret(context.Background(), secret, remote)
		assert.NoError(t, err)
		assert.Equal(t, 1, vaultClient.CancelledCount)
		assert.Equal(t, 1, vaultClient.UpdatedCount)
		assert.Equal(t, secretOCID, vaultClient.LastUpdatedSecretID)
	})

	t.Run("keeps going when cancel reports the secret is already changing", func(t *testing.T) {
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{pending},
			CreateErr:       nameTaken,
			CancelErr: &fakeoracle.ServiceError{
				Code:    409,
				OCICode: "IncorrectState",
				Message: "IncorrectState",
			},
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client: &fakeoracle.OracleMockClient{
				SecretBundles: map[string]secrets.SecretBundle{},
			},
			VaultClient: vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.EqualError(t, err, "oci vault secret \"test1\" is pending deletion until 2026-10-04T12:00:00Z; scheduled deletion was canceled and the secret will be updated once it is active")
		assert.Equal(t, 1, vaultClient.CancelledCount)
		assert.Equal(t, 0, vaultClient.UpdatedCount)
	})

	t.Run("retries without canceling while the secret is still creating", func(t *testing.T) {
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{creating},
			CreateErr:       nameTaken,
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client: &fakeoracle.OracleMockClient{
				SecretBundles: map[string]secrets.SecretBundle{},
			},
			VaultClient: vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.EqualError(t, err, "oci vault secret \"test1\" is CREATING; retry once the vault finishes the previous operation")
		assert.Equal(t, 0, vaultClient.CancelledCount)
		assert.Equal(t, 0, vaultClient.UpdatedCount)
	})

	t.Run("updates an active secret whose bundle read raced with create", func(t *testing.T) {
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{active},
			CreateErr:       nameTaken,
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client: &fakeoracle.OracleMockClient{
				SecretBundles: map[string]secrets.SecretBundle{},
			},
			VaultClient: vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.NoError(t, err)
		assert.Equal(t, 0, vaultClient.CancelledCount)
		assert.Equal(t, 1, vaultClient.UpdatedCount)
		assert.Equal(t, secretOCID, vaultClient.LastUpdatedSecretID)
	})

	t.Run("returns other create errors unchanged", func(t *testing.T) {
		vaultClient := &fakeoracle.OracleMockVaultClient{
			SecretSummaries: []vault.SecretSummary{pending},
			CreateErr:       errors.New("boom"),
		}
		vms := &VaultManagementService{
			encryptionKey: encryptionKey,
			compartment:   compartment,
			vault:         vaultID,
			Client: &fakeoracle.OracleMockClient{
				SecretBundles: map[string]secrets.SecretBundle{},
			},
			VaultClient: vaultClient,
		}

		secret := &corev1.Secret{Data: map[string][]byte{testSecretKey: []byte("restored-value")}}
		err := vms.PushSecret(context.Background(), secret, remote)
		assert.EqualError(t, err, "boom")
		assert.Equal(t, 0, vaultClient.CancelledCount)
		assert.Nil(t, vaultClient.LastListRequest.Name)
	})
}

func TestOracleVaultDeleteSecret(t *testing.T) {
	var testCases = map[string]struct {
		vms       *VaultManagementService
		remoteRef esv1.PushSecretRemoteRef
		validator func(service *VaultManagementService) bool
	}{
		"do not delete if secret not found": {
			&VaultManagementService{
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			esv1alpha1.PushSecretRemoteRef{
				RemoteKey: s2id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).DeletedCount == 0
			},
		},
		"do not delete if secret os already deleting": {
			&VaultManagementService{
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s3id: s3bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			esv1alpha1.PushSecretRemoteRef{
				RemoteKey: s3id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).DeletedCount == 0
			},
		},
		"delete existing secret": {
			&VaultManagementService{
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
						s3id: s3bundle,
					},
				},
				VaultClient: &fakeoracle.OracleMockVaultClient{},
			},
			esv1alpha1.PushSecretRemoteRef{
				RemoteKey: s1id,
			},
			func(vms *VaultManagementService) bool {
				return vms.VaultClient.(*fakeoracle.OracleMockVaultClient).DeletedCount == 1
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			err := testCase.vms.DeleteSecret(context.Background(), testCase.remoteRef)
			assert.NoError(t, err)
			assert.True(t, testCase.validator(testCase.vms))
		})
	}
}

func TestOracleVaultSecretExists(t *testing.T) {
	var testCases = map[string]struct {
		vms       *VaultManagementService
		remoteRef esv1.PushSecretRemoteRef
		ok        bool
	}{
		"ok if secret exists": {
			&VaultManagementService{
				VaultClient: &fakeoracle.OracleMockVaultClient{},
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
					},
				},
			},
			esv1alpha1.PushSecretRemoteRef{
				RemoteKey: s1id,
			},
			true,
		},
		"not ok if secret doesn't exist": {
			&VaultManagementService{
				VaultClient: &fakeoracle.OracleMockVaultClient{},
				Client: &fakeoracle.OracleMockClient{
					SecretBundles: map[string]secrets.SecretBundle{
						s1id: s1bundle,
					},
				},
			},
			esv1alpha1.PushSecretRemoteRef{
				RemoteKey: s2id,
			},
			false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			ok, err := testCase.vms.SecretExists(context.Background(), testCase.remoteRef)
			assert.NoError(t, err)
			assert.Equal(t, testCase.ok, ok)
		})
	}
}

var (
	s1id      = "test1"
	s2id      = "mysecret"
	s3id      = "deleting"
	s1bundle  = makeSecretBundle(s1id, false)
	s2bundle  = makeSecretBundle(s2id, false)
	s3bundle  = makeSecretBundle(s3id, true)
	s1summary = makeSecretSummary(s1id, false)
	s2summary = makeSecretSummary(s2id, false)
	s3summary = makeSecretSummary(s3id, true)
)

func makeSecretBundle(id string, deleting bool) secrets.SecretBundle {
	var deletionTime *common.SDKTime
	if deleting {
		deletionTime = &common.SDKTime{
			Time: time.Now(),
		}
	}
	return secrets.SecretBundle{
		SecretId: &id,
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{
			Content: new(base64.StdEncoding.EncodeToString([]byte(id))),
		},
		TimeOfDeletion: deletionTime,
	}
}

func makeSecretSummary(id string, deleting bool) vault.SecretSummary {
	var deletionTime *common.SDKTime
	if deleting {
		deletionTime = &common.SDKTime{
			Time: time.Now(),
		}
	}
	return vault.SecretSummary{
		Id:             &id,
		SecretName:     &id,
		TimeOfDeletion: deletionTime,
	}
}
