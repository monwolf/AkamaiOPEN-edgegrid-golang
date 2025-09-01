//revive:disable:exported

package accountprotection

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

var _ AccountProtection = &Mock{}

// Transactional Endpoints
func (p *Mock) ListProtectedOperations(ctx context.Context, params ListProtectedOperationsRequest) (*ListProtectedOperationsResponse, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListProtectedOperationsResponse), nil
}
func (p *Mock) GetProtectedOperationByID(ctx context.Context, params GetProtectedOperationByIDRequest) (*ListProtectedOperationsResponse, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListProtectedOperationsResponse), nil
}
func (p *Mock) CreateProtectedOperations(ctx context.Context, params CreateProtectedOperationsRequest) (*ListProtectedOperationsResponse, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ListProtectedOperationsResponse), nil
}
func (p *Mock) UpdateProtectedOperation(ctx context.Context, params UpdateProtectedOperationRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}
func (p *Mock) RemoveProtectedOperation(ctx context.Context, params RemoveProtectedOperationRequest) error {
	args := p.Called(ctx, params)
	return args.Error(0)
}

// General Settings
func (p *Mock) GetGeneralSettings(ctx context.Context, params GetGeneralSettingsRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}
func (p *Mock) UpsertGeneralSettings(ctx context.Context, params UpsertGeneralSettingsRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}

// User Risk Response Strategy
func (p *Mock) GetUserRiskResponseStrategy(ctx context.Context, params GetUserRiskResponseStrategyRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}
func (p *Mock) UpsertUserRiskResponseStrategy(ctx context.Context, params UpsertUserRiskResponseStrategyRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}

// User Allow list Id
func (p *Mock) GetUserAllowListID(ctx context.Context, params GetUserAllowListIDRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), nil
}
func (p *Mock) UpsertUserAllowListID(ctx context.Context, params UpsertUserAllowListIDRequest) (map[string]interface{}, error) {
	args := p.Called(ctx, params)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), nil
}
func (p *Mock) DeleteUserAllowListID(ctx context.Context, params DeleteUserAllowListIDRequest) error {
	args := p.Called(ctx, params)
	return args.Error(0)
}
