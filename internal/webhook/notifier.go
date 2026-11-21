package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// Notifier sends the alert of an analysed run (the analysis calls NotifyRun).
type Notifier struct {
	St     *store.Store
	Log    *slog.Logger
	Client Client
}

func (n *Notifier) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

// NotifyRun posts the summary of run runID when the webhook is enabled and
// the run has a change or a new finding at the minimum severity. The result
// goes to the audit log (integration.webhook.send).
func (n *Notifier) NotifyRun(ctx context.Context, runID int64) {
	s, err := n.St.GetWebhook(ctx, true)
	if err != nil || !s.Enabled || s.URL == "" {
		return
	}
	run, err := n.St.GetRun(ctx, runID)
	if err != nil {
		n.log().Error("webhook: read run", "run", runID, "err", err)
		return
	}
	var changes []model.Change
	_ = n.St.EachChange(ctx, store.ChangeFilter{RunID: runID}, func(c *model.Change) error {
		if len(changes) < 20000 {
			changes = append(changes, *c)
		}
		return nil
	})
	var findings []model.Finding
	_ = n.St.EachFinding(ctx, store.FindingFilter{FirstRunID: runID}, func(f *model.Finding) error {
		if len(findings) < 20000 {
			findings = append(findings, *f)
		}
		return nil
	})
	p, ok := Build(run, changes, findings, s.MinSeverity, s.UIURL)
	if !ok {
		n.log().Debug("webhook: nothing at the minimum severity", "run", runID, "min", s.MinSeverity)
		return
	}
	body, _ := json.Marshal(p)
	res := n.Client.Post(ctx, s.URL, s.Secret, EventRun, body)
	detail := map[string]any{"run_id": runID, "status": res.Status, "ms": res.Ms, "changes": len(p.Changes), "findings": len(p.Findings), "auto": true}
	if res.Error != "" {
		detail["error"] = res.Error
		n.log().Warn("webhook delivery failed", "run", runID, "status", res.Status, "err", res.Error)
	} else {
		n.log().Info("webhook delivered", "run", runID, "status", res.Status, "ms", res.Ms)
	}
	_ = n.St.InsertAudit(ctx, model.AuditEntry{Action: "integration.webhook.send", Entity: "run", EntityID: fmt.Sprint(runID), UserEmail: "system", Detail: detail})
}
