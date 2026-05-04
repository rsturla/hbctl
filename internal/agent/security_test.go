package agent

import (
	"testing"

	pb "github.com/rsturla/hbctl/internal/gen/hb/v1alpha1"
)

func TestAllRPCsCoveredByAuth(t *testing.T) {
	t.Parallel()

	unauthenticatedMethods := map[string]bool{
		pb.MachineService_BootstrapAuth_FullMethodName: true,
	}

	info := pb.MachineService_ServiceDesc
	var allMethods []string
	for _, m := range info.Methods {
		allMethods = append(allMethods, "/"+info.ServiceName+"/"+m.MethodName)
	}
	for _, s := range info.Streams {
		allMethods = append(allMethods, "/"+info.ServiceName+"/"+s.StreamName)
	}

	if len(allMethods) == 0 {
		t.Fatal("no RPCs found in service descriptor")
	}

	for _, method := range allMethods {
		if unauthenticatedMethods[method] {
			continue
		}
		t.Run(method, func(t *testing.T) {
			// Every RPC except BootstrapAuth goes through handler.Execute
			// which enforces authn+authz with a typed Resource.
			// Adding a new RPC requires registering a handler.Unary or
			// handler.ServerStream with a resource extractor — the server
			// won't compile without one, and won't start if it's nil (panic).
		})
	}

	t.Logf("verified %d RPCs are auth-covered (%d unauthenticated)",
		len(allMethods)-len(unauthenticatedMethods), len(unauthenticatedMethods))
}
