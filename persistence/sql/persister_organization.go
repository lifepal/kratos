package sql

import (
	"context"
	"database/sql"
	"github.com/ory/kratos/corp"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/ory/x/sqlcon"

	"github.com/ory/kratos/identity"
)

func (p *Persister) UpdateOrganization(ctx context.Context, i *identity.Organization) error {
	i.NID = corp.ContextualizeNID(ctx, p.nid)
	return sqlcon.HandleError(p.Transaction(ctx, func(ctx context.Context, tx *pop.Connection) error {
		if count, err := tx.Where("id = ? AND nid = ?", i.ID, corp.ContextualizeNID(ctx, p.nid)).Count(i); err != nil {
			return err
		} else if count == 0 {
			return sql.ErrNoRows
		}

		return p.update(WithTransaction(ctx, tx), i)
	}))
}

func (p *Persister) ListOrganizations(ctx context.Context, page, perPage int) ([]identity.Organization, error) {
	is := make([]identity.Organization, 0)

	/* #nosec G201 TableName is static */
	if err := sqlcon.HandleError(p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).
		Paginate(page, perPage).Order("id DESC").
		All(&is)); err != nil {
		return nil, err
	}
	return is, nil
}

func (p *Persister) CreateOrganization(ctx context.Context, i *identity.Organization) error {
	i.NID = corp.ContextualizeNID(ctx, p.nid)

	return p.Transaction(ctx, func(ctx context.Context, tx *pop.Connection) error {
		return tx.Create(i)
	})
}

func (p *Persister) CountOrganizations(ctx context.Context) (int64, error) {
	count, err := p.c.WithContext(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).Count(new(identity.Organization))
	if err != nil {
		return 0, sqlcon.HandleError(err)
	}
	return int64(count), nil
}

func (p *Persister) GetOrganizationDetail(ctx context.Context, id uuid.UUID) (*identity.Organization, error) {
	var i identity.Organization

	nid := corp.ContextualizeNID(ctx, p.nid)
	if err := p.GetConnection(ctx).Where("id = ? AND nid = ?", id, nid).First(&i); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return &i, nil
}

func (p *Persister) DeleteOrganization(ctx context.Context, id uuid.UUID) error {
	return p.delete(ctx, new(identity.Organization), id)
}
