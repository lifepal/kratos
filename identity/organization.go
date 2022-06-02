package identity

import (
	"context"
	"sync"
	"time"

	"github.com/ory/kratos/corp"

	"github.com/gofrs/uuid"
)

type Organization struct {
	l *sync.RWMutex `db:"-" faker:"-"`

	// ID is the identity's unique identifier.
	//
	// The Organization ID can not be changed and can not be chosen. This ensures future
	// compatibility and optimization for distributed stores such as CockroachDB.
	//
	// required: true
	ID uuid.UUID `json:"id" faker:"-" db:"id"`

	// Logo is the identity's state.
	//
	// This value has currently no effect.
	Logo string `json:"logo" faker:"-" db:"logo"`

	// Name is the identity's state.
	//
	// This value has currently no effect.
	Name string `json:"name" faker:"-" db:"name"`

	// Slug is the identity's state.
	//
	// This value has currently no effect.
	Slug string `json:"slug" faker:"-" db:"slug"`

	// LeadsOwner is the identity's state.
	//
	// This value has currently no effect.
	LeadsOwner string `json:"leads_owner" faker:"-" db:"leads_owner"`

	// EnableQa is the identity's state.
	//
	// This value has currently no effect.
	EnableQa bool `json:"enable_qa" faker:"-" db:"enable_qa"`

	// IsActive is the identity's state.
	//
	// This value has currently no effect.
	IsActive bool `json:"is_active" faker:"-" db:"is_active"`

	// ShowCommission is the identity's state.
	//
	// This value has currently no effect.
	ShowCommission bool `json:"show_commission" faker:"-" db:"show_commission"`

	// ShowMemberStructure is the identity's state.
	//
	// This value has currently no effect.
	ShowMemberStructure bool `json:"show_member_structure" faker:"-" db:"show_member_structure"`

	// UseSimpleLeadStatus is the identity's state.
	//
	// This value has currently no effect.
	UseSimpleLeadStatus bool `json:"use_simple_lead_status" faker:"-" db:"use_simple_lead_status"`

	// ShowLevelInDashboard is the identity's state.
	//
	// This value has currently no effect.
	ShowLevelInDashboard bool `json:"show_level_in_dashboard" faker:"-" db:"show_level_in_dashboard"`

	// ShowShortcutsInDashboard is the identity's state.
	//
	// This value has currently no effect.
	ShowShortcutsInDashboard bool `json:"show_shortcuts_in_dashboard" faker:"-" db:"show_shortcuts_in_dashboard"`

	// CreatedAt is a helper struct field for gobuffalo.pop.
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is a helper struct field for gobuffalo.pop.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	NID       uuid.UUID `json:"-"  faker:"-" db:"nid"`
}

func (i Organization) TableName(ctx context.Context) string {
	return corp.ContextualizeTableName(ctx, "organizations")
}

func (i *Organization) lock() *sync.RWMutex {
	if i.l == nil {
		i.l = new(sync.RWMutex)
	}
	return i.l
}

func (i Organization) GetID() uuid.UUID {
	return i.ID
}

func (i Organization) GetNID() uuid.UUID {
	return i.NID
}
