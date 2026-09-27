package version

var (
	Version = "1.0.0"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return Version + " (" + Commit + " " + Date + ")"
}
