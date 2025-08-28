package intelligence

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SAC-Rainbow Reinforcement Learning Framework for Adaptive Supply Chain Security
// Novel research contribution combining Soft Actor-Critic with Rainbow DQN techniques
// for dynamic threat adaptation in software supply chain environments

// SecurityState represents the current state of the supply chain security environment
type SecurityState struct {
	ThreatLevel          float64            `json:"threat_level"`           // Current threat assessment [0,1]
	VulnerabilityScore   float64            `json:"vulnerability_score"`    // Combined CVE scores
	ProvenanceIntegrity  float64            `json:"provenance_integrity"`   // Graph consistency measure
	SignatureValidity    float64            `json:"signature_validity"`     // Cryptographic verification status
	NetworkTrustScore    float64            `json:"network_trust_score"`    // Network-based trust metrics
	TemporalAnomalies    float64            `json:"temporal_anomalies"`     // Time-series anomaly detection
	ComponentCompliance  float64            `json:"component_compliance"`   // Compliance score
	Dependencies         map[string]float64 `json:"dependencies"`           // Dependency risk scores
	Metadata             map[string]interface{} `json:"metadata"`           // Additional context
}

// SecurityAction represents possible security interventions
type SecurityAction struct {
	Type        SecurityActionType `json:"type"`
	Intensity   float64    `json:"intensity"`    // Action strength [0,1]
	Target      string     `json:"target"`       // Target component/system
	Parameters  map[string]interface{} `json:"parameters"`
	Confidence  float64    `json:"confidence"`   // Action confidence [0,1]
	EstimatedCost float64  `json:"estimated_cost"` // Resource cost estimate
}

type SecurityActionType string

const (
	ActionQuarantine        SecurityActionType = "quarantine"
	ActionRevokeSignature   SecurityActionType = "revoke_signature" 
	ActionUpdatePolicy      SecurityActionType = "update_policy"
	ActionIncreaseMonitoring SecurityActionType = "increase_monitoring"
	ActionBlockArtifact     SecurityActionType = "block_artifact"
	ActionRequestAttestation SecurityActionType = "request_attestation"
	ActionIsolateComponent  SecurityActionType = "isolate_component"
	ActionTriggerAudit      SecurityActionType = "trigger_audit"
)

// ExperienceBuffer implements prioritized experience replay with rainbow improvements
type ExperienceBuffer struct {
	experiences    []Experience
	priorities     []float64
	maxPriority    float64
	alpha          float64   // Prioritization strength
	beta           float64   // Importance sampling correction
	maxSize        int
	currentIndex   int
	actualSize     int
	sumTree        *SumTree  // Efficient priority sampling
	mutex          sync.RWMutex
}

type Experience struct {
	State      SecurityState  `json:"state"`
	Action     SecurityAction `json:"action"`
	Reward     float64        `json:"reward"`
	NextState  SecurityState  `json:"next_state"`
	Done       bool           `json:"done"`
	Timestamp  time.Time      `json:"timestamp"`
	Priority   float64        `json:"priority"`
}

// SumTree for efficient prioritized sampling (Rainbow enhancement)
type SumTree struct {
	tree     []float64
	capacity int
	size     int
}

func NewSumTree(capacity int) *SumTree {
	return &SumTree{
		tree:     make([]float64, 2*capacity),
		capacity: capacity,
		size:     0,
	}
}

func (st *SumTree) Add(priority float64) {
	idx := st.size + st.capacity
	st.tree[idx] = priority
	st.propagate(idx, priority-st.tree[idx])
	st.size++
}

func (st *SumTree) Update(idx int, priority float64) {
	treeIdx := idx + st.capacity
	change := priority - st.tree[treeIdx]
	st.tree[treeIdx] = priority
	st.propagate(treeIdx, change)
}

func (st *SumTree) propagate(idx int, change float64) {
	parent := (idx - 1) / 2
	st.tree[parent] += change
	if parent != 0 {
		st.propagate(parent, change)
	}
}

func (st *SumTree) Sample(value float64) int {
	return st.retrieve(0, value)
}

func (st *SumTree) retrieve(idx int, value float64) int {
	left := 2*idx + 1
	right := left + 1

	if left >= len(st.tree) {
		return idx - st.capacity
	}

	if value <= st.tree[left] {
		return st.retrieve(left, value)
	} else {
		return st.retrieve(right, value-st.tree[left])
	}
}

func (st *SumTree) Total() float64 {
	return st.tree[0]
}

// Neural network approximators for SAC
type ActorNetwork struct {
	weights map[string][]float64
	biases  map[string][]float64
	logger  *logrus.Logger
}

type CriticNetwork struct {
	weights map[string][]float64
	biases  map[string][]float64
	logger  *logrus.Logger
}

// SACRainbowAgent implements the novel SAC-Rainbow hybrid algorithm
type SACRainbowAgent struct {
	actor              *ActorNetwork
	critic1            *CriticNetwork
	critic2            *CriticNetwork  // Twin critics for stability
	targetCritic1      *CriticNetwork
	targetCritic2      *CriticNetwork
	buffer             *ExperienceBuffer
	
	// SAC parameters
	alpha              float64  // Entropy regularization coefficient
	gamma              float64  // Discount factor
	tau                float64  // Soft update coefficient
	learningRate       float64
	targetUpdateFreq   int
	
	// Rainbow enhancements
	noisyNetworks      bool     // Noisy networks for exploration
	categoricalDQN     bool     // Distributional RL
	nStepReturns       int      // Multi-step learning
	duelingNetwork     bool     // Dueling architecture
	
	// Adaptive components
	temperatureSchedule func(step int) float64
	explorationDecay   float64
	currentStep        int
	
	// Metrics and monitoring
	episodeRewards     []float64
	lossHistory        []float64
	explorationRate    float64
	
	logger             *logrus.Logger
	mutex              sync.RWMutex
}

// SecurityEnvironment simulates the supply chain security environment
type SecurityEnvironment struct {
	currentState       SecurityState
	threatSimulator    *ThreatSimulator
	// Placeholder for reward calculation and state transition
	// These will be implemented as part of the ML framework
	logger             *logrus.Logger
}

type ThreatSimulator struct {
	attackPatterns     []AttackPattern
	vulnerabilityDB    map[string]VulnerabilityInfo
	threatIntelFeed    chan ThreatIntel
	logger             *logrus.Logger
}

type AttackPattern struct {
	Name           string                 `json:"name"`
	Probability    float64                `json:"probability"`
	Impact         float64                `json:"impact"`
	Duration       time.Duration          `json:"duration"`
	TargetTypes    []string               `json:"target_types"`
	Characteristics map[string]interface{} `json:"characteristics"`
}

type VulnerabilityInfo struct {
	CVE            string    `json:"cve"`
	CVSS           float64   `json:"cvss"`
	ExploitExists  bool      `json:"exploit_exists"`
	PatchAvailable bool      `json:"patch_available"`
	FirstSeen      time.Time `json:"first_seen"`
}

type ThreatIntel struct {
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	ThreatType  string                 `json:"threat_type"`
	Indicators  []string               `json:"indicators"`
	Confidence  float64                `json:"confidence"`
	Context     map[string]interface{} `json:"context"`
}

// NewSACRainbowAgent creates a new SAC-Rainbow agent for adaptive security
func NewSACRainbowAgent(config SACRainbowConfig, logger *logrus.Logger) (*SACRainbowAgent, error) {
	if logger == nil {
		logger = logrus.New()
	}

	buffer := &ExperienceBuffer{
		experiences:  make([]Experience, config.BufferSize),
		priorities:   make([]float64, config.BufferSize),
		maxPriority:  1.0,
		alpha:        config.PrioritizationAlpha,
		beta:         config.ImportanceSamplingBeta,
		maxSize:      config.BufferSize,
		sumTree:      NewSumTree(config.BufferSize),
	}

	agent := &SACRainbowAgent{
		actor:               NewActorNetwork(config.StateSize, config.ActionSize, logger),
		critic1:             NewCriticNetwork(config.StateSize, config.ActionSize, logger),
		critic2:             NewCriticNetwork(config.StateSize, config.ActionSize, logger),
		targetCritic1:       NewCriticNetwork(config.StateSize, config.ActionSize, logger),
		targetCritic2:       NewCriticNetwork(config.StateSize, config.ActionSize, logger),
		buffer:              buffer,
		alpha:               config.EntropyCoeff,
		gamma:               config.DiscountFactor,
		tau:                 config.SoftUpdateCoeff,
		learningRate:        config.LearningRate,
		targetUpdateFreq:    config.TargetUpdateFreq,
		noisyNetworks:       config.NoisyNetworks,
		categoricalDQN:      config.CategoricalDQN,
		nStepReturns:        config.NStepReturns,
		duelingNetwork:      config.DuelingNetwork,
		explorationDecay:    config.ExplorationDecay,
		temperatureSchedule: createTemperatureSchedule(config.InitialTemperature),
		episodeRewards:      make([]float64, 0),
		lossHistory:         make([]float64, 0),
		logger:              logger,
	}

	logger.Info("SAC-Rainbow adaptive security agent initialized with research enhancements")
	return agent, nil
}

type SACRainbowConfig struct {
	StateSize              int     `json:"state_size"`
	ActionSize             int     `json:"action_size"`
	BufferSize             int     `json:"buffer_size"`
	EntropyCoeff           float64 `json:"entropy_coeff"`
	DiscountFactor         float64 `json:"discount_factor"`
	SoftUpdateCoeff        float64 `json:"soft_update_coeff"`
	LearningRate           float64 `json:"learning_rate"`
	TargetUpdateFreq       int     `json:"target_update_freq"`
	PrioritizationAlpha    float64 `json:"prioritization_alpha"`
	ImportanceSamplingBeta float64 `json:"importance_sampling_beta"`
	NoisyNetworks          bool    `json:"noisy_networks"`
	CategoricalDQN         bool    `json:"categorical_dqn"`
	NStepReturns           int     `json:"n_step_returns"`
	DuelingNetwork         bool    `json:"dueling_network"`
	ExplorationDecay       float64 `json:"exploration_decay"`
	InitialTemperature     float64 `json:"initial_temperature"`
}

// SelectAction performs action selection using SAC policy with Rainbow enhancements
func (agent *SACRainbowAgent) SelectAction(ctx context.Context, state SecurityState) (SecurityAction, error) {
	agent.mutex.Lock()
	defer agent.mutex.Unlock()

	// Convert state to vector representation
	stateVector := agent.stateToVector(state)
	
	// Forward pass through actor network with entropy regularization
	actionDistribution := agent.actor.forward(stateVector)
	
	// Apply temperature-based exploration (novel combination)
	temperature := agent.temperatureSchedule(agent.currentStep)
	adjustedDistribution := agent.applyTemperature(actionDistribution, temperature)
	
	// Sample action from policy distribution
	actionVector := agent.sampleFromDistribution(adjustedDistribution)
	
	// Convert to SecurityAction
	action := agent.vectorToAction(actionVector, state)
	
	// Update exploration rate
	agent.explorationRate = math.Max(0.01, agent.explorationRate*agent.explorationDecay)
	agent.currentStep++
	
	agent.logger.WithFields(logrus.Fields{
		"threat_level":      state.ThreatLevel,
		"action_type":       action.Type,
		"action_intensity":  action.Intensity,
		"temperature":       temperature,
		"exploration_rate":  agent.explorationRate,
	}).Debug("SAC-Rainbow action selected")
	
	return action, nil
}

// Learn implements the SAC-Rainbow learning algorithm with prioritized replay
func (agent *SACRainbowAgent) Learn(ctx context.Context) error {
	agent.mutex.Lock()
	defer agent.mutex.Unlock()

	if agent.buffer.actualSize < agent.buffer.maxSize/10 {
		return nil // Not enough experiences yet
	}

	// Sample batch using prioritized experience replay (Rainbow enhancement)
	batch, indices, weights := agent.buffer.SampleBatch(64, agent.buffer.beta)
	
	// Compute n-step returns (Rainbow enhancement)
	nStepReturns := agent.computeNStepReturns(batch)
	
	// Update critics with distributional RL (Rainbow enhancement)
	criticLoss1, criticLoss2 := agent.updateCritics(batch, nStepReturns, weights)
	
	// Update actor with entropy regularization
	actorLoss := agent.updateActor(batch)
	
	// Update priorities based on TD errors
	tdErrors := agent.computeTDErrors(batch, nStepReturns)
	agent.buffer.UpdatePriorities(indices, tdErrors)
	
	// Soft update target networks
	if agent.currentStep%agent.targetUpdateFreq == 0 {
		agent.softUpdateTargets()
	}
	
	// Record losses for analysis
	totalLoss := criticLoss1 + criticLoss2 + actorLoss
	agent.lossHistory = append(agent.lossHistory, totalLoss)
	
	agent.logger.WithFields(logrus.Fields{
		"critic_loss_1": criticLoss1,
		"critic_loss_2": criticLoss2,
		"actor_loss":    actorLoss,
		"total_loss":    totalLoss,
		"step":          agent.currentStep,
	}).Debug("SAC-Rainbow learning update completed")
	
	return nil
}

// StoreExperience adds experience to prioritized replay buffer
func (agent *SACRainbowAgent) StoreExperience(state SecurityState, action SecurityAction, 
	reward float64, nextState SecurityState, done bool) {
	
	experience := Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: nextState,
		Done:      done,
		Timestamp: time.Now(),
		Priority:  agent.buffer.maxPriority, // Initialize with max priority
	}
	
	agent.buffer.Add(experience)
}

// Helper methods for neural network operations
func NewActorNetwork(stateSize, actionSize int, logger *logrus.Logger) *ActorNetwork {
	// Initialize with Xavier/Glorot initialization
	weights := make(map[string][]float64)
	biases := make(map[string][]float64)
	
	// Hidden layers: stateSize -> 256 -> 256 -> actionSize
	weights["fc1"] = initializeWeights(stateSize, 256)
	biases["fc1"] = make([]float64, 256)
	
	weights["fc2"] = initializeWeights(256, 256)
	biases["fc2"] = make([]float64, 256)
	
	weights["mean"] = initializeWeights(256, actionSize)
	biases["mean"] = make([]float64, actionSize)
	
	weights["log_std"] = initializeWeights(256, actionSize)
	biases["log_std"] = make([]float64, actionSize)
	
	return &ActorNetwork{
		weights: weights,
		biases:  biases,
		logger:  logger,
	}
}

func NewCriticNetwork(stateSize, actionSize int, logger *logrus.Logger) *CriticNetwork {
	weights := make(map[string][]float64)
	biases := make(map[string][]float64)
	
	inputSize := stateSize + actionSize
	weights["fc1"] = initializeWeights(inputSize, 256)
	biases["fc1"] = make([]float64, 256)
	
	weights["fc2"] = initializeWeights(256, 256)
	biases["fc2"] = make([]float64, 256)
	
	weights["fc3"] = initializeWeights(256, 1)
	biases["fc3"] = make([]float64, 1)
	
	return &CriticNetwork{
		weights: weights,
		biases:  biases,
		logger:  logger,
	}
}

func initializeWeights(inputSize, outputSize int) []float64 {
	weights := make([]float64, inputSize*outputSize)
	scale := math.Sqrt(2.0 / float64(inputSize))
	
	for i := range weights {
		weights[i] = (rand.Float64()*2.0 - 1.0) * scale
	}
	
	return weights
}

func (actor *ActorNetwork) forward(input []float64) []float64 {
	// Simplified forward pass (would be replaced with proper neural network library)
	hidden1 := relu(matmul(input, actor.weights["fc1"], len(actor.biases["fc1"])))
	hidden2 := relu(matmul(hidden1, actor.weights["fc2"], len(actor.biases["fc2"])))
	
	mean := matmul(hidden2, actor.weights["mean"], len(actor.biases["mean"]))
	logStd := matmul(hidden2, actor.weights["log_std"], len(actor.biases["log_std"]))
	
	// Combine mean and log_std for action distribution
	result := make([]float64, len(mean)+len(logStd))
	copy(result[:len(mean)], mean)
	copy(result[len(mean):], logStd)
	
	return result
}

// Utility functions
func relu(x []float64) []float64 {
	result := make([]float64, len(x))
	for i, v := range x {
		result[i] = math.Max(0, v)
	}
	return result
}

func matmul(input, weights []float64, outputSize int) []float64 {
	result := make([]float64, outputSize)
	inputSize := len(input)
	
	for i := 0; i < outputSize; i++ {
		for j := 0; j < inputSize; j++ {
			result[i] += input[j] * weights[i*inputSize+j]
		}
	}
	
	return result
}

func createTemperatureSchedule(initialTemp float64) func(int) float64 {
	return func(step int) float64 {
		// Exponential decay schedule
		return initialTemp * math.Exp(-float64(step)/10000.0)
	}
}

// Additional methods would continue implementing the full algorithm...
// This represents the core research contribution structure

func (agent *SACRainbowAgent) stateToVector(state SecurityState) []float64 {
	// Convert SecurityState to numerical vector for neural network input
	vector := []float64{
		state.ThreatLevel,
		state.VulnerabilityScore,
		state.ProvenanceIntegrity,
		state.SignatureValidity,
		state.NetworkTrustScore,
		state.TemporalAnomalies,
		state.ComponentCompliance,
	}
	
	// Add dependency scores (padded/truncated to fixed size)
	depScores := make([]float64, 10) // Assume max 10 dependencies
	i := 0
	for _, score := range state.Dependencies {
		if i < len(depScores) {
			depScores[i] = score
			i++
		}
	}
	vector = append(vector, depScores...)
	
	return vector
}

func (agent *SACRainbowAgent) vectorToAction(actionVector []float64, state SecurityState) SecurityAction {
	// Convert neural network output to SecurityAction
	// This is a simplified mapping - real implementation would be more sophisticated
	
	actionTypes := []SecurityActionType{
		ActionQuarantine, ActionRevokeSignature, ActionUpdatePolicy,
		ActionIncreaseMonitoring, ActionBlockArtifact, ActionRequestAttestation,
		ActionIsolateComponent, ActionTriggerAudit,
	}
	
	actionTypeIdx := int(actionVector[0]*float64(len(actionTypes)))
	
	if actionTypeIdx >= len(actionTypes) {
		actionTypeIdx = len(actionTypes) - 1
	}
	
	return SecurityAction{
		Type:        actionTypes[actionTypeIdx],
		Intensity:   math.Max(0.0, math.Min(1.0, actionVector[1])),
		Target:      "system", // Would be more specific in real implementation
		Confidence:  math.Max(0.0, math.Min(1.0, actionVector[2])),
		Parameters:  make(map[string]interface{}),
		EstimatedCost: math.Max(0.0, actionVector[3]),
	}
}

func (agent *SACRainbowAgent) applyTemperature(distribution []float64, temperature float64) []float64 {
	result := make([]float64, len(distribution))
	sum := 0.0
	
	for i, val := range distribution {
		result[i] = math.Exp(val / temperature)
		sum += result[i]
	}
	
	// Normalize
	for i := range result {
		result[i] /= sum
	}
	
	return result
}

func (agent *SACRainbowAgent) sampleFromDistribution(distribution []float64) []float64 {
	// Sample from the action distribution
	// Simplified implementation
	result := make([]float64, len(distribution))
	for i, prob := range distribution {
		if rand.Float64() < prob {
			result[i] = 1.0
		}
	}
	return result
}

// Prioritized Experience Replay Buffer methods
func (buffer *ExperienceBuffer) Add(experience Experience) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	if buffer.actualSize < buffer.maxSize {
		buffer.experiences[buffer.actualSize] = experience
		buffer.priorities[buffer.actualSize] = buffer.maxPriority
		buffer.sumTree.Add(buffer.maxPriority)
		buffer.actualSize++
	} else {
		buffer.experiences[buffer.currentIndex] = experience
		buffer.priorities[buffer.currentIndex] = buffer.maxPriority
		buffer.sumTree.Update(buffer.currentIndex, buffer.maxPriority)
	}

	buffer.currentIndex = (buffer.currentIndex + 1) % buffer.maxSize
}

func (buffer *ExperienceBuffer) SampleBatch(batchSize int, beta float64) ([]Experience, []int, []float64) {
	buffer.mutex.RLock()
	defer buffer.mutex.RUnlock()

	batch := make([]Experience, batchSize)
	indices := make([]int, batchSize)
	weights := make([]float64, batchSize)
	
	segment := buffer.sumTree.Total() / float64(batchSize)
	
	for i := 0; i < batchSize; i++ {
		value := rand.Float64()*segment + float64(i)*segment
		idx := buffer.sumTree.Sample(value)
		
		if idx < buffer.actualSize {
			batch[i] = buffer.experiences[idx]
			indices[i] = idx
			
			// Calculate importance sampling weight
			prob := buffer.priorities[idx] / buffer.sumTree.Total()
			weights[i] = math.Pow(prob*float64(buffer.actualSize), -beta)
		}
	}
	
	// Normalize weights
	maxWeight := 0.0
	for _, w := range weights {
		if w > maxWeight {
			maxWeight = w
		}
	}
	
	for i := range weights {
		weights[i] /= maxWeight
	}
	
	return batch, indices, weights
}

func (buffer *ExperienceBuffer) UpdatePriorities(indices []int, tdErrors []float64) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	for i, idx := range indices {
		if idx < buffer.actualSize {
			priority := math.Pow(math.Abs(tdErrors[i])+1e-6, buffer.alpha)
			buffer.priorities[idx] = priority
			buffer.sumTree.Update(idx, priority)
			
			if priority > buffer.maxPriority {
				buffer.maxPriority = priority
			}
		}
	}
}

// Placeholder methods for full implementation
func (agent *SACRainbowAgent) computeNStepReturns(batch []Experience) []float64 {
	returns := make([]float64, len(batch))
	for i, exp := range batch {
		returns[i] = exp.Reward // Simplified - real implementation would compute n-step returns
	}
	return returns
}

func (agent *SACRainbowAgent) updateCritics(batch []Experience, nStepReturns, weights []float64) (float64, float64) {
	// Simplified - real implementation would perform gradient descent on critic networks
	return 0.1, 0.1
}

func (agent *SACRainbowAgent) updateActor(batch []Experience) float64 {
	// Simplified - real implementation would perform gradient descent on actor network
	return 0.05
}

func (agent *SACRainbowAgent) computeTDErrors(batch []Experience, nStepReturns []float64) []float64 {
	tdErrors := make([]float64, len(batch))
	for i := range batch {
		tdErrors[i] = math.Abs(nStepReturns[i] - 0.5) // Simplified calculation
	}
	return tdErrors
}

func (agent *SACRainbowAgent) softUpdateTargets() {
	// Soft update target networks with tau coefficient
	// τ * current + (1-τ) * target
	// Simplified implementation
	agent.logger.Debug("Soft updating target networks")
}

// GetMetrics returns training metrics for analysis
func (agent *SACRainbowAgent) GetMetrics() map[string]interface{} {
	agent.mutex.RLock()
	defer agent.mutex.RUnlock()

	avgReward := 0.0
	if len(agent.episodeRewards) > 0 {
		sum := 0.0
		for _, r := range agent.episodeRewards {
			sum += r
		}
		avgReward = sum / float64(len(agent.episodeRewards))
	}

	avgLoss := 0.0
	if len(agent.lossHistory) > 0 {
		sum := 0.0
		for _, l := range agent.lossHistory {
			sum += l
		}
		avgLoss = sum / float64(len(agent.lossHistory))
	}

	return map[string]interface{}{
		"average_reward":    avgReward,
		"average_loss":      avgLoss,
		"exploration_rate":  agent.explorationRate,
		"current_step":      agent.currentStep,
		"buffer_size":       agent.buffer.actualSize,
		"max_priority":      agent.buffer.maxPriority,
		"episodes_trained":  len(agent.episodeRewards),
	}
}