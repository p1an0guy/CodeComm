// Package ipc implements CodeComm's authenticated, owner-only local
// transport. It owns endpoint security, HTTP framing, and the mechanical
// bind-before-use state machine. Agent launch and resume authorization belong
// to the agent layer behind Binder.
package ipc
