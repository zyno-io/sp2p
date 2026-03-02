// SPDX-License-Identifier: MIT

package conn

import (
	"context"
	"fmt"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

const upnpTimeout = 5 * time.Second

// UPnPMapping represents an active UPnP port mapping.
type UPnPMapping struct {
	ExternalPort uint16
	InternalPort uint16
	ExternalIP   string
	client       any // underlying UPnP client for cleanup
}


// RemoveMapping removes a UPnP port mapping.
func (m *UPnPMapping) RemoveMapping() {
	if m == nil {
		return
	}
	if client, ok := m.client.(*internetgateway2.WANIPConnection2); ok {
		client.DeletePortMapping("", m.ExternalPort, "TCP")
	}
	if client, ok := m.client.(*internetgateway2.WANIPConnection1); ok {
		client.DeletePortMapping("", m.ExternalPort, "TCP")
	}
}

func discoverAndMap(ctx context.Context, localPort uint16) (*UPnPMapping, error) {
	// Try WANIPConnection2 first (more common on modern routers).
	clients2, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	if err == nil && len(clients2) > 0 {
		client := clients2[0]
		externalIP, err := client.GetExternalIPAddressCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting external IP: %w", err)
		}

		// Try to map the same external port.
		err = client.AddPortMappingCtx(ctx,
			"",          // remote host (empty = any)
			localPort,   // external port
			"TCP",       // protocol
			localPort,   // internal port
			getLocalIP(), // internal client
			true,        // enabled
			"sp2p",      // description
			3600,        // lease duration (1 hour)
		)
		if err != nil {
			return nil, fmt.Errorf("adding port mapping: %w", err)
		}

		return &UPnPMapping{
			ExternalPort: localPort,
			InternalPort: localPort,
			ExternalIP:   externalIP,
			client:       client,
		}, nil
	}

	// Fallback to WANIPConnection1.
	clients1, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	if err == nil && len(clients1) > 0 {
		client := clients1[0]
		externalIP, err := client.GetExternalIPAddressCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting external IP: %w", err)
		}

		err = client.AddPortMappingCtx(ctx, "", localPort, "TCP", localPort,
			getLocalIP(), true, "sp2p", 3600)
		if err != nil {
			return nil, fmt.Errorf("adding port mapping: %w", err)
		}

		return &UPnPMapping{
			ExternalPort: localPort,
			InternalPort: localPort,
			ExternalIP:   externalIP,
			client:       client,
		}, nil
	}

	return nil, fmt.Errorf("no UPnP gateway found")
}

func getLocalIP() string {
	ips := GetLocalIPs()
	if len(ips) > 0 {
		return ips[0]
	}
	return "127.0.0.1"
}
