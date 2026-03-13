package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// Route53DNSProvider manages records via the AWS Route 53 API.
type Route53DNSProvider struct {
	client *route53.Client
}

// NewRoute53DNSProvider constructs a provider using static access key credentials.
// region should be "us-east-1"; Route 53 is a global service but the SDK requires a region.
func NewRoute53DNSProvider(accessKey, secretKey, region string, optFns ...func(*route53.Options)) (*Route53DNSProvider, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("route53: loading AWS config: %w", err)
	}
	return &Route53DNSProvider{client: route53.NewFromConfig(cfg, optFns...)}, nil
}

func (p *Route53DNSProvider) hostedZoneID(ctx context.Context, zone string) (string, error) {
	out, err := p.client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName:  aws.String(zone),
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return "", fmt.Errorf("route53: listing hosted zones: %w", err)
	}
	if len(out.HostedZones) == 0 || !strings.HasPrefix(aws.ToString(out.HostedZones[0].Name), zone) {
		return "", fmt.Errorf("route53: hosted zone not found for %q", zone)
	}
	id := aws.ToString(out.HostedZones[0].Id)
	return strings.TrimPrefix(id, "/hostedzone/"), nil
}

func (p *Route53DNSProvider) change(ctx context.Context, zone, name, typ, value string, ttl int, action types.ChangeAction) error {
	zoneID, err := p.hostedZoneID(ctx, zone)
	if err != nil {
		return err
	}
	if ttl == 0 {
		ttl = 300
	}
	fqdnName := name + "." + zone
	if name == "" || name == "@" {
		fqdnName = zone
	}
	_, err = p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{
				Action: action,
				ResourceRecordSet: &types.ResourceRecordSet{
					Name: aws.String(fqdnName),
					Type: types.RRType(typ),
					TTL:  aws.Int64(int64(ttl)),
					ResourceRecords: []types.ResourceRecord{
						{Value: aws.String(value)},
					},
				},
			}},
		},
	})
	return err
}

func (p *Route53DNSProvider) CreateRecord(zone, name, typ, value string, ttl int) error {
	return p.change(context.Background(), zone, name, typ, value, ttl, types.ChangeActionCreate)
}

func (p *Route53DNSProvider) UpdateRecord(zone, name, typ, value string, ttl int) error {
	return p.change(context.Background(), zone, name, typ, value, ttl, types.ChangeActionUpsert)
}

func (p *Route53DNSProvider) DeleteRecord(zone, name, typ string) error {
	ctx := context.Background()
	zoneID, err := p.hostedZoneID(ctx, zone)
	if err != nil {
		return err
	}
	fqdnName := name + "." + zone
	out, err := p.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(fqdnName),
		StartRecordType: types.RRType(typ),
		MaxItems:        aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("route53: listing records to delete: %w", err)
	}
	if len(out.ResourceRecordSets) == 0 {
		return nil // idempotent
	}
	rrs := out.ResourceRecordSets[0]
	_, err = p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{
				Action:            types.ChangeActionDelete,
				ResourceRecordSet: &rrs,
			}},
		},
	})
	return err
}

func (p *Route53DNSProvider) Present(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.CreateRecord(zone, label, "TXT", `"`+acmeTXTValue(keyAuth)+`"`, 120)
}

func (p *Route53DNSProvider) CleanUp(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(zone, label, "TXT")
}

func (p *Route53DNSProvider) Ping() error {
	_, err := p.client.ListHostedZones(context.Background(), &route53.ListHostedZonesInput{
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("route53: ping failed: %w", err)
	}
	return nil
}

func (p *Route53DNSProvider) Name() string { return "route53" }
