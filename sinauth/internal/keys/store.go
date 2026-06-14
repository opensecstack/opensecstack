package keys

// Store persists key metadata to the database.
// Currently a stub — key material lives on disk (LoadOrGenerate).
// Future: support multiple keys for rotation, storing kid + algorithm + status.
type Store struct{}

// NewStore returns a new Store.
func NewStore() *Store { return &Store{} }
