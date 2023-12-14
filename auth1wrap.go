package auth1lib

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	pb "github.com/DeepXRLab/auth1lib-go/rpcapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Auth1Wrapper struct {
	conn *grpc.ClientConn
	md   metadata.MD
	acli pb.Auth1Client

	defaultTenantKey string
	defaultSiteKey   string
	defaultApiKey    string

	timeoutInSecs time.Duration
	verbose       bool
}

type auth1WrapperOption func(w *Auth1Wrapper)

func WithVerbose() auth1WrapperOption {
	return func(w *Auth1Wrapper) {
		w.verbose = true
	}
}

func WithRequestTimeout(seconds int) auth1WrapperOption {
	return func(w *Auth1Wrapper) {
		w.timeoutInSecs = time.Duration(seconds) * time.Second
	}
}

func NewClient(auth1uri string, opts ...auth1WrapperOption) (*Auth1Wrapper, error) {
	parsed, err := url.ParseRequestURI(auth1uri)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid Auth1 URI(%s): %v", auth1uri, err))
	}
	tenantAndSite := strings.Split(strings.TrimSuffix(strings.TrimPrefix(parsed.Path, "/"), "/"), "/")
	if len(tenantAndSite) != 2 {
		return nil, errors.New(fmt.Sprintf("Invalid Auth1 URI Path(/tenant/site): %s", parsed.Path))
	}

	ret := &Auth1Wrapper{
		timeoutInSecs:    time.Second * 30, // default
		defaultTenantKey: tenantAndSite[0],
		defaultSiteKey:   tenantAndSite[1],
		defaultApiKey:    parsed.User.Username(),
	}

	var creds credentials.TransportCredentials
	if parsed.Scheme == "auth1s" {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})
	} else if parsed.Scheme == "auth1" {
		creds = insecure.NewCredentials()
	} else {
		return nil, errors.New(fmt.Sprintf("Unsupported scheme: %s", parsed.Scheme))
	}

	if ret.defaultApiKey != "" {
		ret.SetApiKey(ret.defaultApiKey)
	}

	for _, opt := range opts {
		opt(ret)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ret.conn, err = grpc.DialContext(ctx, parsed.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		if ret.verbose {
			log.Printf("Auth1: grpc.Dial(%s) failed: %v\n", parsed.Host, err)
		}
		return nil, err
	}

	ret.acli = pb.NewAuth1Client(ret.conn)
	return ret, nil
}

func (wrapper *Auth1Wrapper) Close() error {
	if wrapper.conn != nil {
		err := wrapper.conn.Close()
		wrapper.conn = nil
		if err != nil {
			if wrapper.verbose {
				log.Printf("Auth1: gRPC ClientConn.Close failed: %v\n", err)
			}
			return err
		}
	} else if wrapper.verbose {
		log.Println("Auth1: already closed.")
	}
	return nil
}

func (wrapper *Auth1Wrapper) SetApiKey(apikey string) {
	wrapper.md = metadata.Pairs("apikey", apikey)
}

func (wrapper *Auth1Wrapper) GetSiteJwtSecret(siteKey string) ([]byte, error) {
	if siteKey == "" {
		siteKey = wrapper.defaultSiteKey
	}

	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.GetSiteJwtSecret(ctx, &pb.SiteJwtSecretRequest{SiteKey: siteKey})
	if err != nil {
		return nil, err
	}

	return r.GetJwtSecret(), nil
}
