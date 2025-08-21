package pipeline

import "fmt"

// HealthCheck adds health checking capability to ValidationStage
func (v *ValidationStage) HealthCheck() error {
	// Simple health check - validation is always healthy if validator exists
	if v.validator == nil {
		return fmt.Errorf("validator is not configured")
	}
	return nil
}

// HealthCheck adds health checking capability to TransformationStage
func (t *TransformationStage) HealthCheck() error {
	// Simple health check - transformation is always healthy if transformer exists
	if t.transformer == nil {
		return fmt.Errorf("transformer is not configured")
	}
	return nil
}

// HealthCheck adds health checking capability to PersistenceStage
func (p *PersistenceStage) HealthCheck() error {
	// Simple health check - persistence is always healthy if persister exists
	if p.persister == nil {
		return fmt.Errorf("persister is not configured")
	}
	return nil
}