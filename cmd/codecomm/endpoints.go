package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"

	"github.com/ijonahch/codecomm/internal/domain"
	"github.com/ijonahch/codecomm/internal/ui"
)

func runPeerEndpoint(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"%w: expected peer endpoint add, list, or remove",
			errInvalidCLI,
		)
	}
	switch args[0] {
	case "add":
		return runPeerEndpointAdd(ctx, args[1:], output, errorOutput)
	case "list":
		return runPeerEndpointList(ctx, args[1:], output, errorOutput)
	case "remove":
		return runPeerEndpointRemove(ctx, args[1:], output, errorOutput)
	default:
		return fmt.Errorf(
			"%w: expected peer endpoint add, list, or remove",
			errInvalidCLI,
		)
	}
}

func runPeerEndpointAdd(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm peer endpoint add", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	deviceText := flags.String("device", "", "expected peer device ID")
	addressText := flags.String(
		"address",
		"",
		"literal peer IP and port",
	)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: no positional arguments are allowed", errInvalidCLI)
	}
	options, deviceID, address, err := manualEndpointCLIInputs(
		localFlags,
		*deviceText,
		*addressText,
	)
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.AddManualEndpoint(ctx, deviceID, address)
	if err != nil {
		return err
	}
	return encodeManualEndpointResult(output, result)
}

func runPeerEndpointList(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet("codecomm peer endpoint list", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	deviceText := flags.String("device", "", "optional peer device ID")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: no positional arguments are allowed", errInvalidCLI)
	}
	options, err := localFlags.options()
	if err != nil {
		return err
	}
	var filter domain.DeviceID
	if *deviceText != "" {
		filter = domain.DeviceID(*deviceText)
		if !filter.Valid() {
			return fmt.Errorf("%w: invalid peer device ID", errInvalidCLI)
		}
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.ManualEndpoints(ctx)
	if err != nil {
		return err
	}
	if filter != "" {
		filtered := make([]ui.ManualEndpointStatus, 0, len(result.Endpoints))
		for _, endpoint := range result.Endpoints {
			if endpoint.DeviceID == string(filter) {
				filtered = append(filtered, endpoint)
			}
		}
		result.Endpoints = filtered
	}
	return encodeManualEndpointResult(output, result)
}

func runPeerEndpointRemove(
	ctx context.Context,
	args []string,
	output io.Writer,
	errorOutput io.Writer,
) error {
	flags := flag.NewFlagSet(
		"codecomm peer endpoint remove",
		flag.ContinueOnError,
	)
	flags.SetOutput(errorOutput)
	localFlags := addLocalClientFlags(flags)
	deviceText := flags.String("device", "", "expected peer device ID")
	addressText := flags.String(
		"address",
		"",
		"literal peer IP and port",
	)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errInvalidCLI, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%w: no positional arguments are allowed", errInvalidCLI)
	}
	options, deviceID, address, err := manualEndpointCLIInputs(
		localFlags,
		*deviceText,
		*addressText,
	)
	if err != nil {
		return err
	}
	client, err := dialLocalOperator(ctx, options)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	result, err := client.RemoveManualEndpoint(ctx, deviceID, address)
	if err != nil {
		return err
	}
	return encodeManualEndpointResult(output, result)
}

func manualEndpointCLIInputs(
	localFlags localClientFlagValues,
	deviceText string,
	addressText string,
) (localClientOptions, domain.DeviceID, netip.AddrPort, error) {
	options, err := localFlags.options()
	if err != nil {
		return localClientOptions{}, "", netip.AddrPort{}, err
	}
	deviceID := domain.DeviceID(deviceText)
	address, parseErr := netip.ParseAddrPort(addressText)
	if !deviceID.Valid() ||
		parseErr != nil ||
		address.String() != addressText {
		return localClientOptions{}, "", netip.AddrPort{}, fmt.Errorf(
			"%w: invalid peer device ID or canonical literal address",
			errInvalidCLI,
		)
	}
	return options, deviceID, address, nil
}

func encodeManualEndpointResult(
	output io.Writer,
	value any,
) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("codecomm: encode manual endpoint result: %w", err)
	}
	return nil
}
