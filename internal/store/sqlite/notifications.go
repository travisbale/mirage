package sqlite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// Notifications implements the notificationStore interface defined in the aitm package.
type Notifications struct{ db *DB }

func NewNotificationStore(db *DB) *Notifications {
	return &Notifications{db: db}
}

func (s *Notifications) CreateChannel(ch *aitm.NotificationChannel) error {
	filterJSON, err := json.Marshal(ch.Filter)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO notify_channels (id, type, url, auth_header, filter, enabled, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		ch.ID, string(ch.Type), ch.URL, ch.AuthHeader,
		string(filterJSON), ch.Enabled, ch.CreatedAt.Unix(),
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Notifications) GetChannel(id string) (*aitm.NotificationChannel, error) {
	row := s.db.QueryRow(`SELECT
		id, type, url, auth_header, filter, enabled, created_at
		FROM notify_channels WHERE id = ?`, id)
	ch, err := scanNotificationChannel(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aitm.ErrNotFound
	}
	return ch, err
}

func (s *Notifications) DeleteChannel(id string) error {
	res, err := s.db.Exec(`DELETE FROM notify_channels WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Notifications) ListChannels() ([]*aitm.NotificationChannel, error) {
	rows, err := s.db.Query(`SELECT
		id, type, url, auth_header, filter, enabled, created_at
		FROM notify_channels ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.NotificationChannel
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

func scanNotificationChannel(row scanner) (*aitm.NotificationChannel, error) {
	var (
		ch        aitm.NotificationChannel
		chType    string
		filterStr string
		createdAt int64
	)
	err := row.Scan(
		&ch.ID, &chType, &ch.URL, &ch.AuthHeader,
		&filterStr, &ch.Enabled, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	ch.Type = sdk.ChannelType(chType)
	ch.CreatedAt = time.Unix(createdAt, 0)
	if err := json.Unmarshal([]byte(filterStr), &ch.Filter); err != nil {
		return nil, err
	}
	return &ch, nil
}
