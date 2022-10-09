module github.com/greenstatic/openspa

go 1.18

require (
	github.com/cilium/ebpf v0.9.3
	github.com/emirpasic/gods v1.18.1
	github.com/pkg/errors v0.9.1
	github.com/pquerna/otp v1.3.0
	github.com/prometheus/client_golang v1.13.0
	github.com/prometheus/client_model v0.2.0
	github.com/rs/zerolog v1.28.0
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/cobra v1.5.0
	github.com/stretchr/testify v1.8.0
	github.com/vishvananda/netlink v1.1.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/greenstatic/openspa/internal/xdp v0.0.0-00010101000000-000000000000 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/greenstatic/openspa/internal/xdp => ./internal/xdp
