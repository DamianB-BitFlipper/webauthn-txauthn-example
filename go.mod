module github.com/hbolimovsky/webauthn-example

go 1.12

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/cloudflare/cfssl v1.4.1 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/duo-labs/webauthn v0.0.0-20200714211715-1daaee874e43
	github.com/duo-labs/webauthn.io v0.0.0-20190926134215-35f44a73518f
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/google/go-tpm v0.1.0 // indirect
	github.com/gorilla/mux v1.7.1
	github.com/gorilla/sessions v1.1.3 // indirect
	github.com/jinzhu/gorm v1.9.11 // indirect
	github.com/katzenpost/core v0.0.7 // indirect
	github.com/kr/pty v1.1.8 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.1 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/ugorji/go v1.1.7 // indirect
	golang.org/x/net v0.0.0-20190724013045-ca1201d0de80 // indirect
	golang.org/x/sys v0.0.0-20190726091711-fc99dfbffb4e // indirect
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/tools v0.0.0-20190729092621-ff9f1409240a // indirect
	gopkg.in/square/go-jose.v2 v2.2.2 // indirect
)

replace github.com/duo-labs/webauthn => ./packages/webauthn
