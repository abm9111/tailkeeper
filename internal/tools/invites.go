package tools

import (
	"context"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// DeviceInvite is a device-share invite. inviteUrl is a bearer link and is never
// returned (spec §7.6).
type DeviceInvite struct {
	ID              string    `json:"id" tk:"col"`
	Created         string    `json:"created,omitempty"`
	DeviceID        int64     `json:"deviceId,omitempty"`
	SharerID        int64     `json:"sharerId,omitempty"`
	MultiUse        bool      `json:"multiUse" tk:"col"`
	AllowExitNode   bool      `json:"allowExitNode" tk:"col"`
	Email           string    `json:"email,omitempty" tk:"untrusted,col,personal"`
	LastEmailSentAt string    `json:"lastEmailSentAt,omitempty"`
	Accepted        bool      `json:"accepted" tk:"col"`
	AcceptedBy      *Acceptor `json:"acceptedBy,omitempty"`
}

// Acceptor is who accepted an invite.
type Acceptor struct {
	ID        int64  `json:"id"`
	LoginName string `json:"loginName" tk:"untrusted,personal"`
}

// UserInvite is a user invite. inviteUrl is never returned.
type UserInvite struct {
	ID              string `json:"id" tk:"col"`
	Role            string `json:"role" tk:"col"`
	InviterID       int64  `json:"inviterId,omitempty"`
	Email           string `json:"email,omitempty" tk:"untrusted,col,personal"`
	LastEmailSentAt string `json:"lastEmailSentAt,omitempty" tk:"col"`
}

// DeviceInvitesOutput lists a device's invites.
type DeviceInvitesOutput struct {
	NodeID  string         `json:"nodeId"`
	Invites []DeviceInvite `json:"invites" tk:"rows"`
	Count   int            `json:"count"`
}

// UserInvitesOutput lists open user invites.
type UserInvitesOutput struct {
	Invites []UserInvite `json:"invites" tk:"rows"`
	Count   int          `json:"count"`
}

// InviteRef names one invite.
type InviteRef struct {
	ID string `json:"id" jsonschema:"invite ID"`
}

// Check refuses an ID that cannot be one, before anything is sent.
func (in InviteRef) Check() error { return requireID("id", in.ID) }

func inviteTools() []registry.Tool {
	ui := withOps(readMeta("user_invites_list", "invites", "users", "List open user invites (invite links are never shown).", "users:read"),
		"GET /tailnet/{tailnet}/user-invites")
	ui.Notes = "The OpenAPI document names no OAuth scope for user-invite reads; users:read is assumed and checked by `doctor --probe`."
	uig := withOps(readMeta("user_invite_get", "invites", "user", "Get one user invite (the invite link is never shown).", "users:read"),
		"GET /user-invites/{userInviteId}")
	uig.Notes = ui.Notes
	return []registry.Tool{
		registry.Define(withOps(readMeta("device_invites_list", "invites", "devices", "List a device's share invites (invite links are never shown).", "device_invites:read", "devices:core:read"),
			"GET /tailnet/{tailnet}/devices", "GET /device/{deviceId}/device-invites"), deviceInvitesList),
		registry.Define(withOps(readMeta("device_invite_get", "invites", "device", "Get one device invite (the invite link is never shown).", "device_invites:read"),
			"GET /device-invites/{deviceInviteId}"), deviceInviteGet),
		registry.Define(ui, userInvitesList),
		registry.Define(uig, userInviteGet),
	}
}

func deviceInvitesList(ctx context.Context, env *registry.Env, in DeviceRef) (DeviceInvitesOutput, error) {
	id, err := resolveDevice(ctx, env, in.Device)
	if err != nil {
		return DeviceInvitesOutput{}, err
	}
	var invites []DeviceInvite
	if err := get(ctx, env, api.Path("device/%s/device-invites", id), nil, &invites); err != nil {
		return DeviceInvitesOutput{}, err
	}
	return DeviceInvitesOutput{NodeID: id, Invites: nonNil(invites), Count: len(invites)}, nil
}

func deviceInviteGet(ctx context.Context, env *registry.Env, in InviteRef) (DeviceInvite, error) {
	var inv DeviceInvite
	if err := get(ctx, env, api.Path("device-invites/%s", in.ID), nil, &inv); err != nil {
		return DeviceInvite{}, err
	}
	return inv, nil
}

func userInvitesList(ctx context.Context, env *registry.Env, _ NoInput) (UserInvitesOutput, error) {
	path, err := tailnetPath(env, "/user-invites")
	if err != nil {
		return UserInvitesOutput{}, err
	}
	var invites []UserInvite
	if err := get(ctx, env, path, nil, &invites); err != nil {
		return UserInvitesOutput{}, err
	}
	return UserInvitesOutput{Invites: nonNil(invites), Count: len(invites)}, nil
}

func userInviteGet(ctx context.Context, env *registry.Env, in InviteRef) (UserInvite, error) {
	var inv UserInvite
	if err := get(ctx, env, api.Path("user-invites/%s", in.ID), nil, &inv); err != nil {
		return UserInvite{}, err
	}
	return inv, nil
}
