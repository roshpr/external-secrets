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

package fake

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

type OracleMockVaultClient struct {
	SecretSummaries       []vault.SecretSummary
	CreatedCount          int
	UpdatedCount          int
	DeletedCount          int
	CancelledCount        int
	CreateErr             error
	CancelErr             error
	LastUpdatedSecretID   string
	LastCancelledSecretID string
	LastListRequest       vault.ListSecretsRequest
	// OnCancel runs after a deletion cancel is recorded. Tests use it to make
	// the secret bundle readable again, which is what OCI does once cancel
	// finishes.
	OnCancel func()
}

func (o *OracleMockVaultClient) ListSecrets(_ context.Context, request vault.ListSecretsRequest) (response vault.ListSecretsResponse, err error) {
	o.LastListRequest = request
	items := o.SecretSummaries
	if request.Name != nil {
		filtered := make([]vault.SecretSummary, 0, len(items))
		for _, item := range items {
			if item.SecretName != nil && *item.SecretName == *request.Name {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	return vault.ListSecretsResponse{
		Items: items,
	}, nil
}

func (o *OracleMockVaultClient) CreateSecret(_ context.Context, _ vault.CreateSecretRequest) (response vault.CreateSecretResponse, err error) {
	o.CreatedCount++
	if o.CreateErr != nil {
		return vault.CreateSecretResponse{}, o.CreateErr
	}
	return vault.CreateSecretResponse{}, nil
}

func (o *OracleMockVaultClient) UpdateSecret(_ context.Context, request vault.UpdateSecretRequest) (response vault.UpdateSecretResponse, err error) {
	o.UpdatedCount++
	if request.SecretId != nil {
		o.LastUpdatedSecretID = *request.SecretId
	}
	return vault.UpdateSecretResponse{}, nil
}

func (o *OracleMockVaultClient) ScheduleSecretDeletion(_ context.Context, _ vault.ScheduleSecretDeletionRequest) (response vault.ScheduleSecretDeletionResponse, err error) {
	o.DeletedCount++
	return vault.ScheduleSecretDeletionResponse{}, nil
}

func (o *OracleMockVaultClient) CancelSecretDeletion(_ context.Context, request vault.CancelSecretDeletionRequest) (response vault.CancelSecretDeletionResponse, err error) {
	o.CancelledCount++
	if request.SecretId != nil {
		o.LastCancelledSecretID = *request.SecretId
	}
	if o.OnCancel != nil {
		o.OnCancel()
	}
	if o.CancelErr != nil {
		return vault.CancelSecretDeletionResponse{}, o.CancelErr
	}
	return vault.CancelSecretDeletionResponse{}, nil
}

type OracleMockClient struct {
	getSecret     func(ctx context.Context, request secrets.GetSecretBundleByNameRequest) (response secrets.GetSecretBundleByNameResponse, err error)
	SecretBundles map[string]secrets.SecretBundle
}

func (mc *OracleMockClient) GetSecretBundleByName(ctx context.Context, request secrets.GetSecretBundleByNameRequest) (response secrets.GetSecretBundleByNameResponse, err error) {
	if mc.SecretBundles != nil {
		if bundle, ok := mc.SecretBundles[*request.SecretName]; ok {
			return secrets.GetSecretBundleByNameResponse{
				SecretBundle: bundle,
			}, nil
		}
		return secrets.GetSecretBundleByNameResponse{}, &ServiceError{Code: 404}
	}
	return mc.getSecret(ctx, request)
}

func (mc *OracleMockClient) WithValue(_ secrets.GetSecretBundleByNameRequest, output secrets.GetSecretBundleByNameResponse, err error) {
	if mc != nil {
		mc.getSecret = func(ctx context.Context, paramReq secrets.GetSecretBundleByNameRequest) (secrets.GetSecretBundleByNameResponse, error) {
			return output, err
		}
	}
}

type ServiceError struct {
	Code    int
	Message string
	OCICode string
}

func (s *ServiceError) Error() string {
	return s.Message
}
func (s *ServiceError) GetHTTPStatusCode() int {
	return s.Code
}

func (s *ServiceError) GetMessage() string {
	return s.Message
}

func (s *ServiceError) GetCode() string {
	return s.OCICode
}

func (s *ServiceError) GetOpcRequestID() string {
	return ""
}
