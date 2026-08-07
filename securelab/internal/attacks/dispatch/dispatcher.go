// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package dispatch wires every attack module to the scenarios.AttackDispatcher
// interface, routing step.Kind to the correct implementation.
package dispatch

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/opensecstack/securelab/internal/attacks/api"
	"github.com/opensecstack/securelab/internal/attacks/exfil"
	"github.com/opensecstack/securelab/internal/attacks/network"
	"github.com/opensecstack/securelab/internal/attacks/recon"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// Dispatcher routes a scenarios.StepSpec to the correct attack module.
type Dispatcher struct {
	// API modules
	bola            *api.BOLAAttack
	authBypass      *api.AuthBypassAttack
	massAssignment  *api.MassAssignmentAttack
	rateLimitBypass *api.RateLimitBypassAttack
	ssrf            *api.SSRFAttack
	misconfig       *api.MisconfigAttack

	// Network modules
	synFlood  *network.SYNFlood
	udpFlood  *network.UDPFlood
	httpFlood *network.HTTPFlood
	slowloris *network.Slowloris

	// Recon modules
	portScanner      *recon.PortScanner
	endpointEnum     *recon.EndpointEnumerator
	versionDetect    *recon.VersionDetector

	// Exfil modules
	dataExfil  *exfil.DataExfilAttack
	dnsTunnel  *exfil.DNSTunnelAttack
}

// NewDispatcher instantiates all attack modules and returns a ready Dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		bola:            api.NewBOLAAttack(),
		authBypass:      api.NewAuthBypassAttack(),
		massAssignment:  api.NewMassAssignmentAttack(),
		rateLimitBypass: api.NewRateLimitBypassAttack(),
		ssrf:            api.NewSSRFAttack(),
		misconfig:       api.NewMisconfigAttack(),

		synFlood:  network.NewSYNFlood(),
		udpFlood:  network.NewUDPFlood(),
		httpFlood: network.NewHTTPFlood(),
		slowloris: network.NewSlowloris(),

		portScanner:   recon.NewPortScanner(),
		endpointEnum:  recon.NewEndpointEnumerator(),
		versionDetect: recon.NewVersionDetector(),

		dataExfil: exfil.NewDataExfilAttack(),
		dnsTunnel: exfil.NewDNSTunnelAttack(),
	}
}

// Dispatch executes the attack described by step against targetURL.
// It implements scenarios.AttackDispatcher.
func (d *Dispatcher) Dispatch(ctx context.Context, step scenarios.StepSpec, targetURL string) (bool, error) {
	switch step.Kind {

	// --- API attacks ---

	case "bola":
		result, err := d.bola.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "auth_bypass":
		result, err := d.authBypass.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "mass_assignment":
		result, err := d.massAssignment.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "rate_limit_bypass":
		result, err := d.rateLimitBypass.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "ssrf":
		result, err := d.ssrf.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "misconfig":
		result, err := d.misconfig.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	// --- Network attacks ---

	case "syn_flood":
		ip, port, err := splitNetworkTarget(targetURL)
		if err != nil {
			return false, fmt.Errorf("dispatch: syn_flood: %w", err)
		}
		result, err := d.synFlood.Run(ctx, ip, port, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "udp_flood":
		ip, port, err := splitNetworkTarget(targetURL)
		if err != nil {
			return false, fmt.Errorf("dispatch: udp_flood: %w", err)
		}
		result, err := d.udpFlood.Run(ctx, ip, port, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "http_flood":
		ip, port, err := splitNetworkTarget(targetURL)
		if err != nil {
			return false, fmt.Errorf("dispatch: http_flood: %w", err)
		}
		result, err := d.httpFlood.Run(ctx, ip, port, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "slowloris":
		ip, port, err := splitNetworkTarget(targetURL)
		if err != nil {
			return false, fmt.Errorf("dispatch: slowloris: %w", err)
		}
		result, err := d.slowloris.Run(ctx, ip, port, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	// --- Recon attacks ---

	case "port_scan":
		hostname, err := extractHostname(targetURL)
		if err != nil {
			return false, fmt.Errorf("dispatch: port_scan: %w", err)
		}
		result, err := d.portScanner.Run(ctx, hostname, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "endpoint_enum":
		result, err := d.endpointEnum.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "version_detect":
		result, err := d.versionDetect.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	// --- Exfil attacks ---

	case "data_exfil":
		result, err := d.dataExfil.Run(ctx, targetURL, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	case "dns_tunnel":
		result, err := d.dnsTunnel.Run(ctx, step.Params)
		if err != nil {
			return false, err
		}
		return result.Success, nil

	default:
		return false, fmt.Errorf("dispatch: unknown step kind %q", step.Kind)
	}
}

// splitNetworkTarget parses targetURL and returns the IP address and port
// suitable for network attack modules. If no port is present, "80" is used.
func splitNetworkTarget(targetURL string) (ip, port string, err error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", "", fmt.Errorf("parse URL %q: %w", targetURL, err)
	}
	host := u.Host
	if host == "" {
		return "", "", fmt.Errorf("no host in URL %q", targetURL)
	}

	// If host contains a port, split it.
	if h, p, splitErr := net.SplitHostPort(host); splitErr == nil {
		return h, p, nil
	}

	// No port — use 80 as default.
	return host, "80", nil
}

// extractHostname parses targetURL and returns u.Hostname() (no port).
func extractHostname(targetURL string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("parse URL %q: %w", targetURL, err)
	}
	h := u.Hostname()
	if h == "" {
		return "", fmt.Errorf("no host in URL %q", targetURL)
	}
	return h, nil
}
