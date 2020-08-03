module github.com/terraform-providers/terraform-provider-dme

go 1.13

require (
	github.com/DNSMadeEasy/dme-go-client v1.0.0
	github.com/hashicorp/terraform-plugin-sdk v1.14.0
)

replace github.com/DNSMadeEasy/dme-go-client v1.0.0 => github.com/oss-contrib/dme-go-client v1.0.1
