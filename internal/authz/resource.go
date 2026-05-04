package authz

import "fmt"

type ResourceType string

const (
	ResourceNode    ResourceType = "Node"
	ResourceService ResourceType = "Service"
	ResourceImage   ResourceType = "Image"
	ResourceConfig  ResourceType = "Config"
	ResourcePath    ResourceType = "Path"
)

type Resource struct {
	Type ResourceType
	ID   string
}

func (r Resource) String() string {
	return fmt.Sprintf("%s::%q", r.Type, r.ID)
}

func (r Resource) Validate() error {
	if r.Type == "" {
		return fmt.Errorf("resource type required")
	}
	if r.ID == "" {
		return fmt.Errorf("resource ID required")
	}
	switch r.Type {
	case ResourceNode, ResourceService, ResourceImage, ResourceConfig, ResourcePath:
	default:
		return fmt.Errorf("unknown resource type: %q", r.Type)
	}
	return nil
}

func NodeResource(id string) Resource    { return Resource{Type: ResourceNode, ID: id} }
func ServiceResource(name string) Resource { return Resource{Type: ResourceService, ID: name} }
func ImageResource(ref string) Resource  { return Resource{Type: ResourceImage, ID: ref} }
func ConfigResource(key string) Resource { return Resource{Type: ResourceConfig, ID: key} }
func PathResource(path string) Resource  { return Resource{Type: ResourcePath, ID: path} }

func ThisNode() Resource { return Resource{Type: ResourceNode, ID: "*"} }
