package version

// Set via ldflags at build time.
var (
	Version      = "dev"
	GitCommit    = "unknown"
	GitTreeState = "unknown"
	BuildDate    = "unknown"
)
