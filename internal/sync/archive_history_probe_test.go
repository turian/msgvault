package sync

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/store"
)

// Development-only archive replay. This file is confined to the CI probe branch.
// No network or credential access occurs; provider event ordering is controlled.
type archiveHistoryTransport struct {
	account string
	ids     [2]string
	starts  []uint64
}

func (f *archiveHistoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.Host != "gmail.googleapis.com" {
		return nil, fmt.Errorf("unexpected replay request")
	}
	var body any
	switch {
	case strings.HasSuffix(r.URL.Path, "/profile"):
		body = map[string]any{"emailAddress": f.account, "historyId": "2000", "messagesTotal": 1}
	case strings.HasSuffix(r.URL.Path, "/labels"):
		body = map[string]any{"labels": []map[string]string{{"id": "INBOX", "name": "INBOX", "type": "system"}, {"id": "TRASH", "name": "TRASH", "type": "system"}}}
	case strings.HasSuffix(r.URL.Path, "/messages"):
		body = map[string]any{"messages": []map[string]string{{"id": f.ids[0]}}}
	case strings.HasSuffix(r.URL.Path, "/history"):
		start, err := strconv.ParseUint(r.URL.Query().Get("startHistoryId"), 10, 64)
		if err != nil {
			return nil, err
		}
		f.starts = append(f.starts, start)
		history := []any{}
		if start < 1500 {
			history = append(history, map[string]any{"id": "1500", "labelsAdded": []any{map[string]any{"message": map[string]string{"id": f.ids[0]}, "labelIds": []string{"TRASH"}}}, "labelsRemoved": []any{map[string]any{"message": map[string]string{"id": f.ids[0]}, "labelIds": []string{"INBOX"}}}, "messagesDeleted": []any{map[string]any{"message": map[string]string{"id": f.ids[1]}}}})
		}
		body = map[string]any{"historyId": "2000", "history": history}
	default:
		return nil, fmt.Errorf("unexpected replay endpoint; raw fetch is forbidden")
	}
	return gmailJSONResponse(r, http.StatusOK, body)
}
func TestArchiveHistoryReplay(t *testing.T) {
	path := os.Getenv("MSGVAULT_REPLAY_COPY")
	if path == "" {
		t.Skip("explicit disposable archive required")
	}
	ctx := t.Context()
	st, err := store.OpenContext(ctx, path)
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.InitSchemaContext(ctx))
	var sid int64
	require.NoError(t, st.DB().QueryRowContext(ctx, "SELECT source_id FROM messages WHERE deleted_at IS NULL AND deleted_from_source_at IS NULL AND EXISTS (SELECT 1 FROM message_raw r WHERE r.message_id=messages.id) GROUP BY source_id HAVING COUNT(*)>=2 ORDER BY COUNT(*) LIMIT 1").Scan(&sid))
	source, err := st.GetSourceByIDContext(ctx, sid)
	require.NoError(t, err)
	f := &archiveHistoryTransport{account: source.Identifier}
	rows, err := st.DB().QueryContext(ctx, "SELECT id,source_message_id FROM messages WHERE source_id=? AND deleted_at IS NULL AND deleted_from_source_at IS NULL AND EXISTS (SELECT 1 FROM message_raw r WHERE r.message_id=messages.id) ORDER BY id LIMIT 2", sid)
	require.NoError(t, err)
	var mids [2]int64
	for i := 0; rows.Next(); i++ {
		require.Less(t, i, 2)
		require.NoError(t, rows.Scan(&mids[i], &f.ids[i]))
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	var rawHashes [2][32]byte
	for i, mid := range mids {
		raw, err := st.GetMessageRaw(mid)
		require.NoError(t, err)
		rawHashes[i] = sha256.Sum256(raw)
	}
	_, err = st.DB().ExecContext(ctx, "UPDATE sources SET sync_cursor='1000' WHERE id=?", sid)
	require.NoError(t, err)
	// Only the disposable copy is changed. The original archive remains read-only.
	api := gmailTransportClient(t, f)
	engine := New(api, st, nil)
	engine.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	summary, err := engine.Full(ctx, source.Identifier)
	require.NoError(t, err)
	assert.Zero(t, summary.Errors)
	assert.Zero(t, summary.MessagesAdded)
	assert.Empty(t, f.starts)
	source, err = st.GetSourceByIDContext(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, "1000", source.SyncCursor.String, "pending History survives the full backfill")
	_, err = engine.Incremental(ctx, source)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1000}, f.starts)
	var trash, inbox int
	require.NoError(t, st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM message_labels ml JOIN labels l ON l.id=ml.label_id WHERE ml.message_id=? AND l.source_label_id='TRASH'", mids[0]).Scan(&trash))
	require.NoError(t, st.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM message_labels ml JOIN labels l ON l.id=ml.label_id WHERE ml.message_id=? AND l.source_label_id='INBOX'", mids[0]).Scan(&inbox))
	assert.Equal(t, 1, trash)
	assert.Zero(t, inbox)
	var absent bool
	require.NoError(t, st.DB().QueryRowContext(ctx, "SELECT deleted_from_source_at IS NOT NULL FROM messages WHERE id=?", mids[1]).Scan(&absent))
	assert.True(t, absent)
	for i, mid := range mids {
		raw, err := st.GetMessageRaw(mid)
		require.NoError(t, err)
		assert.True(t, rawHashes[i] == sha256.Sum256(raw), "archived raw preserved")
	}
	source, err = st.GetSourceByIDContext(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, "2000", source.SyncCursor.String)
}
