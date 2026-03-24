package sqlite

import (
	"database/sql"
	"errors"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// Operators implements the operatorStore interface defined in the aitm package.
type Operators struct{ db *DB }

func NewOperatorStore(db *DB) *Operators { return &Operators{db: db} }

func (s *Operators) CreateOperator(op *aitm.Operator) error {
	_, err := s.db.db.Exec(
		`INSERT INTO operators (name, created_at) VALUES (?, ?)`,
		op.Name, op.CreatedAt.Unix(),
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Operators) ListOperators() ([]*aitm.Operator, error) {
	rows, err := s.db.db.Query(`SELECT name, created_at FROM operators ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.Operator
	for rows.Next() {
		op, err := scanOperator(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (s *Operators) DeleteOperator(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM operators WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Operators) CreateInvite(invite *aitm.OperatorInvite) error {
	_, err := s.db.db.Exec(
		`INSERT INTO operator_invites (token, name, expires_at) VALUES (?, ?, ?)`,
		invite.Token, invite.Name, invite.ExpiresAt.Unix(),
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Operators) ConsumeInvite(token string) (*aitm.OperatorInvite, error) {
	var invite aitm.OperatorInvite
	err := s.db.WithTx(func(tx *sql.Tx) error {
		var expiresAt int64
		err := tx.QueryRow(
			`SELECT token, name, expires_at FROM operator_invites WHERE token = ?`, token,
		).Scan(&invite.Token, &invite.Name, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return aitm.ErrNotFound
		}
		if err != nil {
			return err
		}
		invite.ExpiresAt = time.Unix(expiresAt, 0)

		_, err = tx.Exec(`DELETE FROM operator_invites WHERE token = ?`, token)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

func scanOperator(row scanner) (*aitm.Operator, error) {
	var (
		op        aitm.Operator
		createdAt int64
	)
	if err := row.Scan(&op.Name, &createdAt); err != nil {
		return nil, err
	}
	op.CreatedAt = time.Unix(createdAt, 0)
	return &op, nil
}
