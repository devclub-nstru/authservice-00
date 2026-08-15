package rbac_test

import (
	"testing"

	"kael/internal/rbac"

	"github.com/google/uuid"
)

func TestPermissionDTO(t *testing.T) {
	desc := "Read access to document resources"
	req := rbac.CreatePermissionRequest{
		Name:        "document",
		Value:       "read",
		Description: &desc,
	}

	if req.Name != "document" || req.Value != "read" {
		t.Fatalf("expected name document and value read, got %s:%s", req.Name, req.Value)
	}
}

func TestGroupDTO(t *testing.T) {
	pID1 := uuid.New()
	pID2 := uuid.New()
	desc := "Editor role"

	req := rbac.CreateGroupRequest{
		Name:          "Editor",
		Description:   &desc,
		PermissionIDs: []uuid.UUID{pID1, pID2},
	}

	if req.Name != "Editor" || len(req.PermissionIDs) != 2 {
		t.Fatalf("expected group Editor with 2 perms, got %s with %d perms", req.Name, len(req.PermissionIDs))
	}
}
