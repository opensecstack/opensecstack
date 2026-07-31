module github.com/opensecstack/community

go 1.25

require (
	github.com/SherClockHolmes/webpush-go v1.4.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.4
	github.com/meilisearch/meilisearch-go v0.36.2
	github.com/opensecstack/sdk/go/citadel v0.0.0
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.50.0
	golang.org/x/image v0.40.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/opensecstack/sdk/go/citadel => ../sdk/go/citadel
