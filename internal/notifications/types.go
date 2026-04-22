package notifications

import "github.com/darksol/Vanta/pkg/types"

// EventType represents the type of notification event
type EventType string

const (
	EventApprovalNeeded  EventType = "approval_needed"
	EventApprovalDecided EventType = "approval_decided"
	EventAuditEntry      EventType = "audit_entry"
)

// Event represents a notification event that can be sent to multiple channels.
// Data must be one of *types.ApprovalRequest, *types.ApprovalDecisionData, or *types.AuditEntry
type Event struct {
	Type         EventType       `json:"type"`
	Data         types.EventData `json:"data"`
	Channel      string          `json:"channel,omitempty"` // Source channel for audit purposes
	TargetUserID string          `json:"-"`                 // If set, SSE delivers only to this user; never sent over the wire
}
