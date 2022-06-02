package sql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/kratos/credentialmigrate"

	"github.com/ory/kratos/corp"

	"github.com/ory/jsonschema/v3"
	"github.com/ory/x/sqlxx"

	"github.com/ory/kratos/otp"
	"github.com/ory/kratos/x"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlcon"

	"github.com/ory/kratos/identity"
)

var _ identity.Pool = new(Persister)
var _ identity.PrivilegedPool = new(Persister)

var (
	Comparison = map[identity.ComparisonType]string{
		identity.ComparisonEqual:            "=",
		identity.ComparisonGreaterThan:      ">",
		identity.ComparisonLessThan:         "<",
		identity.ComparisonGreaterThanEqual: ">=",
		identity.ComparisonLessThanEqual:    "<=",
		identity.ComparisonNotEqual:         "<>",
		identity.ComparisonIn:               "in",
		identity.ComparisonLike:             "like",
	}
	// ConnectionDialect format will be (key -> field -> comparison -> value)
	ConnectionDialect = map[string]string{
		"sqlite3":   `json_extract(%s, '$.%s') %s ?`,
		"mysql":     `json_extract(%s, '$.%s') %s ?`,
		"mariadb":   `json_extract(%s, '$.%s') %s ?`,
		"postgres":  `%s %s ?`,
		"cockroach": `%s %s ?`,
	}
)

func (p *Persister) ListVerifiableAddresses(ctx context.Context, page, itemsPerPage int) (a []identity.VerifiableAddress, err error) {
	if err := p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).Order("id DESC").Paginate(page, x.MaxItemsPerPage(itemsPerPage)).All(&a); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return a, err
}

func (p *Persister) ListRecoveryAddresses(ctx context.Context, page, itemsPerPage int) (a []identity.RecoveryAddress, err error) {
	if err := p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).Order("id DESC").Paginate(page, x.MaxItemsPerPage(itemsPerPage)).All(&a); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return a, err
}

func stringToLowerTrim(match string) string {
	return strings.ToLower(strings.TrimSpace(match))
}

func (p *Persister) normalizeIdentifier(ct identity.CredentialsType, match string) string {
	switch ct {
	case identity.CredentialsTypeLookup:
		// lookup credentials are case-sensitive
		return match
	case identity.CredentialsTypeTOTP:
		// totp credentials are case-sensitive
		return match
	case identity.CredentialsTypeOIDC:
		// OIDC credentials are case-sensitive
		return match
	case identity.CredentialsTypePassword:
		fallthrough
	case identity.CredentialsTypeWebAuthn:
		return stringToLowerTrim(match)
	}
	return match
}

func (p *Persister) FindByCredentialsIdentifier(ctx context.Context, ct identity.CredentialsType, match string) (*identity.Identity, *identity.Credentials, error) {
	nid := corp.ContextualizeNID(ctx, p.nid)

	var cts []identity.CredentialsTypeTable
	if err := p.GetConnection(ctx).All(&cts); err != nil {
		return nil, nil, sqlcon.HandleError(err)
	}

	var find struct {
		IdentityID uuid.UUID `db:"identity_id"`
	}

	// Force case-insensitivity and trimming for identifiers
	match = p.normalizeIdentifier(ct, match)

	// #nosec G201
	if err := p.GetConnection(ctx).RawQuery(fmt.Sprintf(`SELECT
    ic.identity_id
FROM %s ic
         INNER JOIN %s ict on ic.identity_credential_type_id = ict.id
         INNER JOIN %s ici on ic.id = ici.identity_credential_id
WHERE ici.identifier = ?
  AND ic.nid = ?
  AND ici.nid = ?
  AND ict.name = ?`,
		corp.ContextualizeTableName(ctx, "identity_credentials"),
		corp.ContextualizeTableName(ctx, "identity_credential_types"),
		corp.ContextualizeTableName(ctx, "identity_credential_identifiers"),
	),
		match,
		nid,
		nid,
		ct,
	).First(&find); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil, sqlcon.HandleError(err) // herodot.ErrNotFound.WithTrace(err).WithReasonf(`No identity matching credentials identifier "%s" could be found.`, match)
		}

		return nil, nil, sqlcon.HandleError(err)
	}

	i, err := p.GetIdentityConfidential(ctx, find.IdentityID)
	if err != nil {
		return nil, nil, err
	}

	creds, ok := i.GetCredentials(ct)
	if !ok {
		return nil, nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("The SQL adapter failed to return the appropriate credentials_type \"%s\". This is a bug in the code.", ct))
	}

	return i.CopyWithoutCredentials(), creds, nil
}

func (p *Persister) findIdentityCredentialsType(ctx context.Context, ct identity.CredentialsType) (*identity.CredentialsTypeTable, error) {
	var m identity.CredentialsTypeTable
	if err := p.GetConnection(ctx).Where("name = ?", ct).First(&m); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	return &m, nil
}

func (p *Persister) createIdentityCredentials(ctx context.Context, i *identity.Identity) error {
	c := p.GetConnection(ctx)

	nid := corp.ContextualizeNID(ctx, p.nid)
	for k := range i.Credentials {
		cred := i.Credentials[k]

		if len(cred.Config) == 0 {
			cred.Config = sqlxx.JSONRawMessage("{}")
		}

		ct, err := p.findIdentityCredentialsType(ctx, cred.Type)
		if err != nil {
			return err
		}

		cred.IdentityID = i.ID
		cred.NID = nid
		cred.CredentialTypeID = ct.ID
		if err := c.Create(&cred); err != nil {
			return sqlcon.HandleError(err)
		}

		for _, ids := range cred.Identifiers {
			// Force case-insensitivity and trimming for identifiers
			ids = p.normalizeIdentifier(cred.Type, ids)

			if len(ids) == 0 {
				return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to create identity credentials with missing or empty identifier."))
			}

			if err := c.Create(&identity.CredentialIdentifier{
				Identifier:                ids,
				IdentityCredentialsID:     cred.ID,
				IdentityCredentialsTypeID: ct.ID,
				NID:                       corp.ContextualizeNID(ctx, p.nid),
			}); err != nil {
				return sqlcon.HandleError(err)
			}
		}

		i.Credentials[k] = cred
	}

	return nil
}

func (p *Persister) createVerifiableAddresses(ctx context.Context, i *identity.Identity) error {
	for k := range i.VerifiableAddresses {
		i.VerifiableAddresses[k].IdentityID = i.ID
		i.VerifiableAddresses[k].NID = corp.ContextualizeNID(ctx, p.nid)
		i.VerifiableAddresses[k].Value = stringToLowerTrim(i.VerifiableAddresses[k].Value)
		if err := p.GetConnection(ctx).Create(&i.VerifiableAddresses[k]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Persister) createRecoveryAddresses(ctx context.Context, i *identity.Identity) error {
	for k := range i.RecoveryAddresses {
		i.RecoveryAddresses[k].IdentityID = i.ID
		i.RecoveryAddresses[k].NID = corp.ContextualizeNID(ctx, p.nid)
		i.RecoveryAddresses[k].Value = stringToLowerTrim(i.RecoveryAddresses[k].Value)
		if err := p.GetConnection(ctx).Create(&i.RecoveryAddresses[k]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Persister) findVerifiableAddresses(ctx context.Context, i *identity.Identity) error {
	var addresses []identity.VerifiableAddress
	if err := p.GetConnection(ctx).Where("identity_id = ? AND nid = ?", i.ID, corp.ContextualizeNID(ctx, p.nid)).Order("id ASC").All(&addresses); err != nil {
		return err
	}
	i.VerifiableAddresses = addresses
	return nil
}

func (p *Persister) findRecoveryAddresses(ctx context.Context, i *identity.Identity) error {
	var addresses []identity.RecoveryAddress
	if err := p.GetConnection(ctx).Where("identity_id = ? AND nid = ?", i.ID, corp.ContextualizeNID(ctx, p.nid)).Order("id ASC").All(&addresses); err != nil {
		return err
	}
	i.RecoveryAddresses = addresses
	return nil
}

func (p *Persister) CountIdentities(ctx context.Context) (int64, error) {
	count, err := p.c.WithContext(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).Count(new(identity.Identity))
	if err != nil {
		return 0, sqlcon.HandleError(err)
	}
	return int64(count), nil
}

func (p *Persister) CreateIdentity(ctx context.Context, i *identity.Identity) error {
	i.NID = corp.ContextualizeNID(ctx, p.nid)

	if i.SchemaID == "" {
		i.SchemaID = p.r.Config(ctx).DefaultIdentityTraitsSchemaID()
	}

	stateChangedAt := sqlxx.NullTime(time.Now())
	i.StateChangedAt = &stateChangedAt
	if i.State == "" {
		i.State = identity.StateActive
	}

	if len(i.Traits) == 0 {
		i.Traits = identity.Traits("{}")
	}

	if err := p.injectTraitsSchemaURL(ctx, i); err != nil {
		return err
	}

	if err := p.validateIdentity(ctx, i); err != nil {
		return err
	}

	return p.Transaction(ctx, func(ctx context.Context, tx *pop.Connection) error {
		if err := tx.Create(i); err != nil {
			return sqlcon.HandleError(err)
		}

		if err := p.createVerifiableAddresses(ctx, i); err != nil {
			return sqlcon.HandleError(err)
		}

		if err := p.createRecoveryAddresses(ctx, i); err != nil {
			return sqlcon.HandleError(err)
		}

		return p.createIdentityCredentials(ctx, i)
	})
}

func (p *Persister) constructIdentityFilter(_ context.Context, filters []*identity.FilterIdentityBody) ([]*identity.FilterIdentityBody, error) {
	// change comparison string to sql format
	for k, v := range filters {
		// if filter is doesn't match with map comparison fallback to equals
		if _, ok := Comparison[v.Comparison]; !ok {
			filters[k].Comparison = identity.ComparisonEqual
			continue
		}
		// if query comparison is like then add %keyName%
		if v.Comparison == identity.ComparisonLike {
			filters[k].Value = "'%" + v.Value + "%'"
		}

		filters[k].Comparison = identity.ComparisonType(Comparison[v.Comparison])
	}
	return filters, nil
}

func (p *Persister) buildIdentityFilterScope(ctx context.Context, filters []*identity.FilterIdentityBody) pop.ScopeFunc {
	return func(q *pop.Query) *pop.Query {
		for _, v := range filters {
			dialect, ok := ConnectionDialect[p.Connection(ctx).Dialect.Name()]
			if !ok {
				return q
			}

			// if dialect is postgres and cockroach and formatting filter as key->>'key'
			if dialect == ConnectionDialect["postgres"] || dialect == ConnectionDialect["cockroach"] {
				sp := strings.Split(v.Key, ".")
				// if len less than 1 then this filter is not complete
				// this should be traits.keyName
				if len(sp) <= 1 {
					sp = []string{"traits", sp[0]}
				}
				v.Key = sp[0]
				for _, qu := range sp[1:] {
					v.Key += fmt.Sprintf(`->>'%s'`, qu)
				}
			}

			// if query is where in
			if v.Comparison == identity.ComparisonIn {
				qFormat := fmt.Sprintf("%s %s (?)", v.Key, v.Comparison)
				q = q.Where(qFormat, v.Values)
				continue
			}

			// if query comparison in like then no need to add query param
			if v.Comparison == identity.ComparisonLike {
				qFormat := fmt.Sprintf("%s %s %s", v.Key, v.Comparison, v.Value)
				q = q.Where(qFormat)
				continue
			}

			comparison := fmt.Sprintf(dialect, v.Key, v.Comparison)
			q = q.Where(comparison, v.Value)
		}
		return q
	}
}

func (p *Persister) DetailIdentitiesFiltered(ctx context.Context, filter identity.AdminFilterIdentityBody) (*identity.Identity, error) {
	is := new(identity.Identity)

	// validate equality filter
	filters, err := p.constructIdentityFilter(ctx, filter.Filters)
	if err != nil {
		return nil, err
	}

	/* #nosec G201 TableName is static */
	if err := sqlcon.HandleError(p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).
		EagerPreload("VerifiableAddresses", "RecoveryAddresses").
		Order("id DESC").
		Scope(p.buildIdentityFilterScope(ctx, filters)).
		First(is)); err != nil {
		return nil, err
	}
	return is, nil
}

func (p *Persister) ListIdentitiesFiltered(ctx context.Context, filter identity.AdminFilterIdentityBody, page, perPage int) ([]identity.Identity, error) {
	is := make([]identity.Identity, 0)

	// validate equality filter
	filters, err := p.constructIdentityFilter(ctx, filter.Filters)
	if err != nil {
		return nil, err
	}

	/* #nosec G201 TableName is static */
	if err := sqlcon.HandleError(p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).
		EagerPreload("VerifiableAddresses", "RecoveryAddresses").
		Paginate(page, perPage).Order("id DESC").
		Scope(p.buildIdentityFilterScope(ctx, filters)).
		All(&is)); err != nil {
		return nil, err
	}

	schemaCache := map[string]string{}

	for k := range is {
		i := &is[k]
		if err := i.ValidateNID(); err != nil {
			return nil, sqlcon.HandleError(err)
		}

		if u, ok := schemaCache[i.SchemaID]; ok {
			i.SchemaURL = u
		} else {
			if err := p.injectTraitsSchemaURL(ctx, i); err != nil {
				return nil, err
			}
			schemaCache[i.SchemaID] = i.SchemaURL
		}

		is[k] = *i
	}

	return is, nil
}

func (p *Persister) ListIdentities(ctx context.Context, page, perPage int) ([]identity.Identity, error) {
	is := make([]identity.Identity, 0)

	/* #nosec G201 TableName is static */
	if err := sqlcon.HandleError(p.GetConnection(ctx).Where("nid = ?", corp.ContextualizeNID(ctx, p.nid)).
		EagerPreload("VerifiableAddresses", "RecoveryAddresses").
		Paginate(page, perPage).Order("id DESC").
		All(&is)); err != nil {
		return nil, err
	}

	schemaCache := map[string]string{}

	for k := range is {
		i := &is[k]
		if err := i.ValidateNID(); err != nil {
			return nil, sqlcon.HandleError(err)
		}

		if u, ok := schemaCache[i.SchemaID]; ok {
			i.SchemaURL = u
		} else {
			if err := p.injectTraitsSchemaURL(ctx, i); err != nil {
				return nil, err
			}
			schemaCache[i.SchemaID] = i.SchemaURL
		}

		is[k] = *i
	}

	return is, nil
}

func (p *Persister) UpdateIdentity(ctx context.Context, i *identity.Identity) error {
	if err := p.validateIdentity(ctx, i); err != nil {
		return err
	}

	i.NID = corp.ContextualizeNID(ctx, p.nid)
	return sqlcon.HandleError(p.Transaction(ctx, func(ctx context.Context, tx *pop.Connection) error {
		if count, err := tx.Where("id = ? AND nid = ?", i.ID, corp.ContextualizeNID(ctx, p.nid)).Count(i); err != nil {
			return err
		} else if count == 0 {
			return sql.ErrNoRows
		}

		for _, tn := range []string{
			new(identity.Credentials).TableName(ctx),
			new(identity.VerifiableAddress).TableName(ctx),
			new(identity.RecoveryAddress).TableName(ctx),
		} {
			/* #nosec G201 TableName is static */
			if err := tx.RawQuery(fmt.Sprintf(
				`DELETE FROM %s WHERE identity_id = ? AND nid = ?`, tn), i.ID, corp.ContextualizeNID(ctx, p.nid)).Exec(); err != nil {
				return err
			}
		}

		if err := p.update(WithTransaction(ctx, tx), i); err != nil {
			return err
		}

		if err := p.createVerifiableAddresses(ctx, i); err != nil {
			return err
		}

		if err := p.createRecoveryAddresses(ctx, i); err != nil {
			return err
		}

		return p.createIdentityCredentials(ctx, i)
	}))
}

func (p *Persister) DeleteIdentity(ctx context.Context, id uuid.UUID) error {
	return p.delete(ctx, new(identity.Identity), id)
}

func (p *Persister) GetIdentity(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	var i identity.Identity
	if err := p.GetConnection(ctx).Where("id = ? AND nid = ?", id, corp.ContextualizeNID(ctx, p.nid)).First(&i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	i.Credentials = nil

	if err := p.findVerifiableAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.findRecoveryAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.injectTraitsSchemaURL(ctx, &i); err != nil {
		return nil, err
	}

	return &i, nil
}

func (p *Persister) GetIdentityConfidentialByEmail(ctx context.Context, email string) (*identity.Identity, error) {
	var i identity.Identity

	nid := corp.ContextualizeNID(ctx, p.nid)
	if err := p.GetConnection(ctx).Where("traits->>'email' = ? AND nid = ?", email, nid).First(&i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	i.Credentials = nil

	if err := p.findVerifiableAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.findRecoveryAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.injectTraitsSchemaURL(ctx, &i); err != nil {
		return nil, err
	}

	return &i, nil
}

func (p *Persister) GetIdentityConfidentialByPhoneNumber(ctx context.Context, phoneNumber string) (*identity.Identity, error) {
	var i identity.Identity

	nid := corp.ContextualizeNID(ctx, p.nid)
	if err := p.GetConnection(ctx).Where("traits->>'phone' = ? AND nid = ?", phoneNumber, nid).First(&i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	i.Credentials = nil

	if err := p.findVerifiableAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.findRecoveryAddresses(ctx, &i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if err := p.injectTraitsSchemaURL(ctx, &i); err != nil {
		return nil, err
	}

	return &i, nil
}

func (p *Persister) GetIdentityConfidential(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	var i identity.Identity

	nid := corp.ContextualizeNID(ctx, p.nid)
	if err := p.GetConnection(ctx).Where("id = ? AND nid = ?", id, nid).First(&i); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	var creds identity.CredentialsCollection
	if err := p.GetConnection(ctx).Where("identity_id = ? AND nid = ?", id, nid).All(&creds); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	i.Credentials = make(map[identity.CredentialsType]identity.Credentials)
	for k := range creds {
		cred := &creds[k]

		var ct identity.CredentialsTypeTable
		if err := p.GetConnection(ctx).Find(&ct, cred.CredentialTypeID); err != nil {
			return nil, sqlcon.HandleError(err)
		}
		cred.Type = ct.Name

		var cids identity.CredentialIdentifierCollection
		if err := p.GetConnection(ctx).Where("identity_credential_id = ? AND nid = ?", cred.ID, nid).All(&cids); err != nil {
			return nil, sqlcon.HandleError(err)
		}

		cred.Identifiers = make([]string, len(cids))
		for kk, cid := range cids {
			cred.Identifiers[kk] = cid.Identifier
		}

		i.Credentials[cred.Type] = *cred
	}

	if err := credentialmigrate.UpgradeCredentials(&i); err != nil {
		return nil, err
	}

	if err := p.findRecoveryAddresses(ctx, &i); err != nil {
		return nil, err
	}
	if err := p.findVerifiableAddresses(ctx, &i); err != nil {
		return nil, err
	}

	if err := p.injectTraitsSchemaURL(ctx, &i); err != nil {
		return nil, err
	}

	return &i, nil
}

func (p *Persister) FindVerifiableAddressByValue(ctx context.Context, via identity.VerifiableAddressType, value string) (*identity.VerifiableAddress, error) {
	var address identity.VerifiableAddress
	if err := p.GetConnection(ctx).Where("nid = ? AND via = ? AND value = ?", corp.ContextualizeNID(ctx, p.nid), via, stringToLowerTrim(value)).First(&address); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return &address, nil
}

func (p *Persister) FindRecoveryAddressByValue(ctx context.Context, via identity.RecoveryAddressType, value string) (*identity.RecoveryAddress, error) {
	var address identity.RecoveryAddress
	if err := p.GetConnection(ctx).Where("nid = ? AND via = ? AND value = ?", corp.ContextualizeNID(ctx, p.nid), via, stringToLowerTrim(value)).First(&address); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return &address, nil
}

func (p *Persister) VerifyAddress(ctx context.Context, code string) error {
	newCode, err := otp.New()
	if err != nil {
		return err
	}

	count, err := p.GetConnection(ctx).RawQuery(
		/* #nosec G201 TableName is static */
		fmt.Sprintf(
			"UPDATE %s SET status = ?, verified = true, verified_at = ?, code = ? WHERE nid = ? AND code = ? AND expires_at > ?",
			new(identity.VerifiableAddress).TableName(ctx),
		),
		identity.VerifiableAddressStatusCompleted,
		time.Now().UTC().Round(time.Second),
		newCode,
		corp.ContextualizeNID(ctx, p.nid),
		code,
		time.Now().UTC(),
	).ExecWithCount()
	if err != nil {
		return sqlcon.HandleError(err)
	}

	if count == 0 {
		return sqlcon.HandleError(sqlcon.ErrNoRows)
	}

	return nil
}

func (p *Persister) UpdateVerifiableAddress(ctx context.Context, address *identity.VerifiableAddress) error {
	address.NID = corp.ContextualizeNID(ctx, p.nid)
	address.Value = stringToLowerTrim(address.Value)
	return p.update(ctx, address)
}

func (p *Persister) validateIdentity(ctx context.Context, i *identity.Identity) error {
	if err := p.r.IdentityValidator().ValidateWithRunner(ctx, i); err != nil {
		if _, ok := errorsx.Cause(err).(*jsonschema.ValidationError); ok {
			return errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
		}
		return err
	}

	return nil
}

func (p *Persister) injectTraitsSchemaURL(ctx context.Context, i *identity.Identity) error {
	ss, err := p.r.IdentityTraitsSchemas(ctx)
	if err != nil {
		return err
	}
	s, err := ss.GetByID(i.SchemaID)
	if err != nil {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf(
			`The JSON Schema "%s" for this identity's traits could not be found.`, i.SchemaID))
	}
	i.SchemaURL = s.SchemaURL(p.r.Config(ctx).SelfPublicURL()).String()
	return nil
}
