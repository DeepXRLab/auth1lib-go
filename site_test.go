package auth1lib_test

import (
	"testing"

	"github.com/DeepXRLab/auth1lib-go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInvalidUri(t *testing.T) {
	_, err := auth1lib.NewClient("localhost:50051")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("http://localhost:50051")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("https://localhost:50051")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("auth1://localhost:50051")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("auth1x://localhost:443")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("auth1s://localhost:443/tenant")
	assert.NotNil(t, err)

	_, err = auth1lib.NewClient("auth1s://localhost:443/tenant/site")
	assert.Nil(t, err)
}

func TestServerUnavailable(t *testing.T) {
	cli, err := auth1lib.NewClient("auth1://xxx:1234/a/b", auth1lib.WithVerbose())
	assert.Nil(t, err, "NewClient failed")

	_, err = cli.GetSiteJwtSecret("yyy")
	assert.NotNil(t, err)
	assert.Equal(t, status.Code(err), codes.Unavailable)

	assert.Nil(t, cli.Close())
}

func TestGetJwtSecret(t *testing.T) {
	cli, err := auth1lib.NewClient("auth1://2ZTLhg28pF6a2eSbAeHn2UUHyFy2ZTLhaqCgsT0yvo4G63nR6G9QqK@localhost:50051/hello/world")
	assert.Nil(t, err, "NewClient failed")

	secret, err := cli.GetSiteJwtSecret("")
	assert.Nil(t, err, "GetSiteJwtSecret failed")
	assert.GreaterOrEqual(t, len(secret), 20)

	// invalid site key
	secret, err = cli.GetSiteJwtSecret("xxxx")
	assert.NotNil(t, err)
	assert.Equal(t, status.Code(err), codes.NotFound)

	// invalid api key
	cli.SetApiKey("xxx")
	_, err = cli.GetSiteJwtSecret("yyy")
	assert.NotNil(t, err)
	assert.Equal(t, status.Code(err), codes.Unauthenticated)

	assert.Nil(t, cli.Close())
}
