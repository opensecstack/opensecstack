// Package opensecstack provides Go client libraries for the opensecstack
// platform: APIGuard (API security scanning), NIS2 Compass (compliance
// management), and CITADEL (governance engine).
//
// # Quick start
//
//	client := opensecstack.NewAPIGuardClient("https://api.example.com", token)
//	scan, err := client.CreateScan(ctx, opensecstack.CreateScanRequest{...})
package opensecstack
