package cedar

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cedarlib "github.com/cedar-policy/cedar-go"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"github.com/rsturla/hbctl/internal/authn"
	"github.com/rsturla/hbctl/internal/authz"
)

const defaultPolicyDir = "/var/lib/hummingbird/policies"

type Config struct {
	PolicyDir string `json:"policy_dir"`
}

type Provider struct {
	mu        sync.RWMutex
	policies  *cedarlib.PolicySet
	entities  cedartypes.EntityMap
	policyDir string
}

func New(cfg json.RawMessage) (authz.Authorizer, error) {
	var c Config
	if cfg != nil {
		if err := json.Unmarshal(cfg, &c); err != nil {
			return nil, fmt.Errorf("parse cedar config: %w", err)
		}
	}
	if c.PolicyDir == "" {
		c.PolicyDir = defaultPolicyDir
	}

	p := &Provider{
		policyDir: c.PolicyDir,
		entities:  cedartypes.EntityMap{},
	}

	if err := p.loadPolicies(); err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	return p, nil
}

func (p *Provider) Name() string { return "cedar" }

func (p *Provider) Authorize(_ context.Context, identity authn.Identity, action string, resource authz.Resource) (authz.Decision, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	principal := cedarlib.NewEntityUID("User", cedartypes.String(identity.Name))

	rpcName := action
	if idx := strings.LastIndex(action, "/"); idx >= 0 {
		rpcName = action[idx+1:]
	}
	cedarAction := cedarlib.NewEntityUID("Action", cedartypes.String(rpcName))

	cedarResource := cedarlib.NewEntityUID(cedartypes.EntityType(resource.Type), cedartypes.String(resource.ID))

	entities := p.buildEntities(identity)

	req := cedartypes.Request{
		Principal: principal,
		Action:    cedarAction,
		Resource:  cedarResource,
		Context:   cedartypes.NewRecord(cedartypes.RecordMap{}),
	}

	decision, diag := p.policies.IsAuthorized(entities, req)

	if len(diag.Errors) > 0 {
		for _, e := range diag.Errors {
			slog.Warn("cedar policy error", "error", e.String(), "policy", e.PolicyID)
		}
	}

	if decision == cedarlib.Allow {
		return authz.Allow, nil
	}
	return authz.Deny, nil
}

func (p *Provider) buildEntities(identity authn.Identity) cedartypes.EntityMap {
	entities := cedartypes.EntityMap{}

	userUID := cedarlib.NewEntityUID("User", cedartypes.String(identity.Name))

	var groupUIDs []cedartypes.EntityUID
	for _, group := range identity.Groups {
		groupUID := cedarlib.NewEntityUID("Group", cedartypes.String(group))
		groupUIDs = append(groupUIDs, groupUID)
		entities[groupUID] = cedartypes.Entity{UID: groupUID}
	}

	entities[userUID] = cedartypes.Entity{
		UID:     userUID,
		Parents: cedartypes.NewEntityUIDSet(groupUIDs...),
	}

	return entities
}

func (p *Provider) loadPolicies() error {
	entries, err := os.ReadDir(p.policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("cedar policy dir not found, using default deny", "dir", p.policyDir)
			p.policies = cedarlib.NewPolicySet()
			return nil
		}
		return fmt.Errorf("read policy dir: %w", err)
	}

	ps := cedarlib.NewPolicySet()
	policyCount := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cedar") {
			continue
		}

		path := filepath.Join(p.policyDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		filePolicies, err := cedarlib.NewPolicySetFromBytes(entry.Name(), data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		for _, policy := range filePolicies.All() {
			id := cedartypes.PolicyID(fmt.Sprintf("%s:%d", entry.Name(), policyCount))
			ps.Add(id, policy)
			policyCount++
		}

		slog.Info("loaded cedar policy", "file", entry.Name())
	}

	p.policies = ps
	return nil
}
