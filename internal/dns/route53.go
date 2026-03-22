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
func NewRoute53DNSProvider(ctx context.Context, accessKey, secretKey, region string, optFns ...func(*route53.Options)) (*Route53DNSProvider, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
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
	rawID := aws.ToString(out.HostedZones[0].Id)
	return strings.TrimPrefix(rawID, "/hostedzone/"), nil
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
	if err != nil {
		return fmt.Errorf("route53: %s %s %s: %w", action, typ, name, err)
	}
	return nil
}

func (p *Route53DNSProvider) CreateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	return p.change(ctx, zone, name, typ, value, ttl, types.ChangeActionCreate)
}

func (p *Route53DNSProvider) UpdateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	return p.change(ctx, zone, name, typ, value, ttl, types.ChangeActionUpsert)
}

func (p *Route53DNSProvider) DeleteRecord(ctx context.Context, zone, name, typ string) error {
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
	rrSet := out.ResourceRecordSets[0]
	_, err = p.client.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{
				Action:            types.ChangeActionDelete,
				ResourceRecordSet: &rrSet,
			}},
		},
	})
	if err != nil {
		return fmt.Errorf("route53: DeleteRecord %s %s: %w", typ, name, err)
	}
	return nil
}

func (p *Route53DNSProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.CreateRecord(ctx, zone, label, "TXT", `"`+acmeTXTValue(keyAuth)+`"`, 120)
}

func (p *Route53DNSProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(ctx, zone, label, "TXT")
}

func (p *Route53DNSProvider) Ping(ctx context.Context) error {
	_, err := p.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{
		MaxItems: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("route53: ping failed: %w", err)
	}
	return nil
}

func (p *Route53DNSProvider) Name() string { return "route53" }
