package labelprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/gmail"
	"go.kenn.io/msgvault/internal/store"
	vaultsync "go.kenn.io/msgvault/internal/sync"
)

type exportedMessage struct {
	ID     string   `json:"id"`
	Raw    []byte   `json:"raw"`
	Labels []string `json:"labels"`
}
type labelDescriptor struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
type archiveExport struct {
	Format   string                     `json:"format"`
	Cursor   string                     `json:"cursor"`
	Catalog  map[string]labelDescriptor `json:"catalog"`
	Messages []exportedMessage          `json:"messages"`
}
type observationTransport struct {
	fixture                       archiveExport
	expected                      map[string][]string
	mu                            sync.Mutex
	metadata, listings, forbidden int
}

func response(r *http.Request, code int, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
}
func (f *observationTransport) reject(r *http.Request) (*http.Response, error) {
	f.forbidden++
	return response(r, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "offline probe rejected request"}})
}
func (f *observationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "gmail.googleapis.com" || r.URL.User != nil {
		return f.reject(r)
	}
	p := r.URL.Path
	q := r.URL.Query()
	switch p {
	case "/gmail/v1/users/me/profile":
		if len(q) != 0 {
			return f.reject(r)
		}
		return response(r, 200, map[string]any{"emailAddress": "reader@example.test", "historyId": f.fixture.Cursor, "messagesTotal": len(f.fixture.Messages), "threadsTotal": len(f.fixture.Messages)})
	case "/gmail/v1/users/me/labels":
		if len(q) != 0 {
			return f.reject(r)
		}
		labels := []map[string]string{}
		for id, l := range f.fixture.Catalog {
			labels = append(labels, map[string]string{"id": id, "name": l.Name, "type": l.Type})
		}
		return response(r, 200, map[string]any{"labels": labels})
	case "/gmail/v1/users/me/messages":
		for k := range q {
			if !slices.Contains([]string{"pageToken", "maxResults", "includeSpamTrash", "fields"}, k) {
				return f.reject(r)
			}
		}
		if q.Get("includeSpamTrash") != "true" {
			return f.reject(r)
		}
		begin, end, next := 0, 2, "p2"
		if q.Get("pageToken") == "p2" {
			begin, end, next = 2, len(f.fixture.Messages), ""
		} else if q.Get("pageToken") != "" {
			return f.reject(r)
		}
		messages := []map[string]string{}
		for i := begin; i < end; i++ {
			messages = append(messages, map[string]string{"id": f.fixture.Messages[i].ID, "threadId": fmt.Sprintf("probe-thread-%d", i)})
		}
		f.listings++
		return response(r, 200, map[string]any{"messages": messages, "nextPageToken": next, "resultSizeEstimate": len(f.fixture.Messages)})
	default:
		const prefix = "/gmail/v1/users/me/messages/"
		if !strings.HasPrefix(p, prefix) || len(q) != 2 || q.Get("format") != "metadata" || q.Get("fields") != "id,labelIds" {
			return f.reject(r)
		}
		id := strings.TrimPrefix(p, prefix)
		labels, ok := f.expected[id]
		if !ok {
			return f.reject(r)
		}
		f.metadata++
		if len(labels) == 0 {
			return response(r, 200, map[string]any{"id": id})
		}
		return response(r, 200, map[string]any{"id": id, "labelIds": labels})
	}
}

type noNetwork struct{}

func (noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	return response(r, http.StatusForbidden, map[string]any{"error": map[string]any{"code": 403, "message": "network disabled"}})
}

func TestOwnedArchiveLabelRefresh(t *testing.T) {
	input := os.Getenv("MSGVAULT_PROBE_EXPORT")
	if input == "" {
		t.Skip("requires a private bounded archive export")
	}
	require.Equal(t, "1", os.Getenv("MSGVAULT_PROBE_ISOLATED"), "run only through the isolated local controller")
	input, err := filepath.EvalSymlinks(input)
	require.NoError(t, err)
	root, err := filepath.EvalSymlinks(os.Getenv("MSGVAULT_PROBE_ROOT"))
	require.NoError(t, err)
	require.Equal(t, root, filepath.Dir(input))
	info, err := os.Lstat(input)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Zero(t, info.Mode().Perm()&0077)
	require.Less(t, info.Size(), int64(12<<20))
	rootInfo, err := os.Stat(root)
	require.NoError(t, err)
	require.Zero(t, rootInfo.Mode().Perm()&0077)
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	var fixture archiveExport
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.Equal(t, "msgvault-owned-label-probe-v1", fixture.Format)
	require.Len(t, fixture.Messages, 4)
	_, err = strconv.ParseUint(fixture.Cursor, 10, 64)
	require.NoError(t, err)
	for _, m := range fixture.Messages {
		require.NotEmpty(t, m.ID)
		require.NotEmpty(t, m.Raw)
		require.NotEmpty(t, m.Labels)
		for _, id := range m.Labels {
			_, ok := fixture.Catalog[id]
			require.True(t, ok)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(logger)
	transport := &observationTransport{fixture: fixture, expected: map[string][]string{}}
	for _, m := range fixture.Messages {
		transport.expected[m.ID] = slices.Clone(m.Labels)
	}
	// The third real message exercises a controlled complete empty observation.
	transport.expected[fixture.Messages[2].ID] = nil
	oldClient, oldTransport := http.DefaultClient, http.DefaultTransport
	http.DefaultTransport = noNetwork{}
	http.DefaultClient = &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() { http.DefaultClient = oldClient; http.DefaultTransport = oldTransport })
	negative, err := http.DefaultClient.Get("https://example.invalid/blocked")
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, negative.StatusCode)
	require.NoError(t, negative.Body.Close())
	require.Equal(t, 1, transport.forbidden)
	transport.forbidden = 0
	// The binary receives only the bounded export; the original archive path is never supplied.
	scratch, err := os.MkdirTemp(root, "store-")
	require.NoError(t, err)
	st, err := store.OpenContext(ctx, filepath.Join(scratch, "archive.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.InitSchemaContext(ctx))
	src, err := st.GetOrCreateSourceContext(ctx, "gmail", "reader@example.test")
	require.NoError(t, err)
	catalog := map[string]store.LabelInfo{}
	for id, l := range fixture.Catalog {
		catalog[id] = store.LabelInfo{Name: l.Name, Type: l.Type}
	}
	// This label exists only in the controlled catalog and scratch Store.
	catalog["Label_probe_extra"] = store.LabelInfo{Name: "Probe extra", Type: "user"}
	fixture.Catalog["Label_probe_extra"] = labelDescriptor{Name: "Probe extra", Type: "user"}
	labelMap, err := st.EnsureLabelsBatch(ctx, src.ID, catalog)
	require.NoError(t, err)
	require.NoError(t, st.UpdateSourceSyncState(ctx, src.ID, fixture.Cursor))
	ids := make([]int64, len(fixture.Messages))
	hashes := make([][32]byte, len(ids))
	want := make([][]int64, len(ids))
	for i, m := range fixture.Messages {
		conversation, createErr := st.EnsureConversationWithTypeContext(ctx, src.ID, fmt.Sprintf("probe-thread-%d", i), "email", "")
		require.NoError(t, createErr)
		initial := []int64{}
		for _, label := range m.Labels {
			initial = append(initial, labelMap[label])
		}
		ids[i], err = st.PersistMessageContext(ctx, &store.MessagePersistData{Message: &store.Message{SourceID: src.ID, SourceMessageID: m.ID, ConversationID: conversation, MessageType: "email", Subject: sql.NullString{String: "Local archive label check", Valid: true}}, RawMIME: m.Raw, RawFormat: "mime", LabelIDs: initial})
		require.NoError(t, err)
		hashes[i] = sha256.Sum256(m.Raw)
		for _, label := range transport.expected[m.ID] {
			want[i] = append(want[i], labelMap[label])
		}
		slices.Sort(want[i])
	}
	// Three changes exist only in this scratch Store: missing, extra, and clear-all.
	_, err = st.ReconcileMessageLabels(ctx, ids[0], nil, true)
	require.NoError(t, err)
	oldLabels, err := st.MessageLabelIDsContext(ctx, ids[1])
	require.NoError(t, err)
	extra := labelMap["Label_probe_extra"]
	require.NotZero(t, extra, "sample needs a catalog label absent from its second message")
	_, err = st.ReconcileMessageLabels(ctx, ids[1], append(oldLabels, extra), true)
	require.NoError(t, err)
	api := gmail.NewClient(nil, gmail.WithLogger(logger))
	opts := vaultsync.DefaultOptions()
	ordinary, err := vaultsync.New(api, st, opts).WithLogger(logger).Full(ctx, "reader@example.test")
	require.NoError(t, err)
	require.Zero(t, ordinary.MessagesAdded)
	require.Zero(t, ordinary.MessagesUpdated)
	require.Zero(t, transport.metadata)
	stale := 0
	for i, id := range ids {
		got, e := st.MessageLabelIDsContext(ctx, id)
		require.NoError(t, e)
		slices.Sort(got)
		if !slices.Equal(want[i], got) {
			stale++
		}
	}
	require.Equal(t, 3, stale, "ordinary full retains the three deliberate mismatches")
	opts.RefreshLabels = true
	updates := []int64{}
	for attempt := 0; attempt < 2; attempt++ {
		summary, runErr := vaultsync.New(api, st, opts).WithLogger(logger).Full(ctx, "reader@example.test")
		require.NoError(t, runErr)
		require.Zero(t, summary.MessagesAdded)
		updates = append(updates, summary.MessagesUpdated)
		for i, id := range ids {
			got, e := st.MessageLabelIDsContext(ctx, id)
			require.NoError(t, e)
			slices.Sort(got)
			assert.True(t, slices.Equal(want[i], got), "membership matches complete controlled observation")
			raw, e := st.GetMessageRawContext(ctx, id)
			require.NoError(t, e)
			assert.Equal(t, hashes[i], sha256.Sum256(raw), "owned RAW bytes retained")
		}
		current, e := st.GetSourceByIDContext(ctx, src.ID)
		require.NoError(t, e)
		assert.True(t, current.SyncCursor.String == fixture.Cursor, "consumed History cursor retained")
	}
	require.Equal(t, []int64{3, 0}, updates)
	require.Equal(t, 8, transport.metadata)
	require.Equal(t, 6, transport.listings)
	require.Zero(t, transport.forbidden)
	require.False(t, t.Failed(), "all probe invariants must pass before writing a success receipt")
	report := map[string]any{"result": "PASS", "owned_messages": 4, "deliberate_mismatches": 3, "ordinary_full_mismatches_remaining": 3, "refresh_changed_memberships": 3, "second_refresh_changes": 0, "metadata_requests": transport.metadata, "listing_requests": transport.listings, "raw_requests": 0, "history_requests": 0, "unexpected_requests": transport.forbidden, "raw_hashes_preserved": true, "cursor_preserved": true, "provider_responses": "controlled offline", "cli_daemon_path_exercised": false, "whole_archive_migration_exercised": false}
	encoded, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "result-private.json"), encoded, 0600))
}
