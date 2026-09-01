package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
)

// remoteCapabilityBinding keeps Identity's existing timeout, retry and
// circuit-breaker transport while implementing the shared capability facet.
// The complete disclosure is validated and cached at Open time; candidate
// validation remains an owner call.
type remoteCapabilityBinding struct {
	client     *client
	summary    modulecapability.ModuleSummary
	categories map[string]modulecapability.CategoryDocument
}

func openCapabilityBinding(ctx context.Context, client *client, expectedSHA256 string) (*remoteCapabilityBinding, error) {
	if client == nil {
		return nil, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.client_unavailable"}
	}
	if err := modulecapability.ValidateRemoteExpectation("identity", expectedSHA256); err != nil {
		return nil, err
	}
	value := &remoteCapabilityBinding{client: client}
	if err := client.doJSON(ctx, http.MethodGet, modulecapability.SummaryPath, client.serviceAccessToken, nil, &value.summary); err != nil {
		return nil, err
	}
	if err := modulecapability.ValidateModuleSummary(value.summary); err != nil || value.summary.Identity.Key != "identity" {
		return nil, &identity.Error{StatusCode: http.StatusConflict, Code: "identity.capability_contract_mismatch", Cause: err}
	}
	if value.summary.Identity.ContractSHA256 != strings.TrimSpace(expectedSHA256) {
		return nil, &identity.Error{StatusCode: http.StatusConflict, Code: "identity.capability_contract_mismatch"}
	}
	value.categories = make(map[string]modulecapability.CategoryDocument, len(value.summary.Categories))
	documents := make([]modulecapability.CategoryDocument, 0, len(value.summary.Categories))
	for _, category := range value.summary.Categories {
		var document modulecapability.CategoryDocument
		if err := client.doJSON(ctx, http.MethodGet, modulecapability.CategoriesPath+category.Key, client.serviceAccessToken, nil, &document); err != nil {
			return nil, err
		}
		value.categories[category.Key] = document
		documents = append(documents, document)
	}
	if err := modulecapability.ValidateBundle(value.summary, documents); err != nil {
		return nil, &identity.Error{StatusCode: http.StatusConflict, Code: "identity.capability_contract_mismatch", Cause: err}
	}
	return value, nil
}

func (value *remoteCapabilityBinding) CapabilitySummary(context.Context) (modulecapability.ModuleSummary, error) {
	return capabilityClone(value.summary)
}

func (value *remoteCapabilityBinding) CapabilityCategory(_ context.Context, key string) (modulecapability.CategoryDocument, error) {
	document, found := value.categories[strings.TrimSpace(key)]
	if !found {
		return modulecapability.CategoryDocument{}, &modulecapability.Error{StatusCode: http.StatusNotFound, Code: "module_capability.category_not_found"}
	}
	return capabilityClone(document)
}

func (value *remoteCapabilityBinding) ValidateCapabilityCandidate(ctx context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	var result modulecapability.ValidationResult
	if err := value.client.doJSON(ctx, http.MethodPost, modulecapability.ValidationPath, value.client.serviceAccessToken, request, &result); err != nil {
		return modulecapability.ValidationResult{}, err
	}
	if err := modulecapability.ValidateValidationResult(result, value.summary.Identity, request.CategoryKey); err != nil {
		return modulecapability.ValidationResult{}, &identity.Error{StatusCode: http.StatusConflict, Code: "identity.capability_contract_mismatch", Cause: err}
	}
	return result, nil
}

func capabilityClone[T any](source T) (T, error) {
	var result T
	payload, err := modulecapability.CanonicalJSON(source)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return result, err
	}
	return result, nil
}

var _ modulecapability.Binding = (*remoteCapabilityBinding)(nil)
