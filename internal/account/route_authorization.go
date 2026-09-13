package account

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

const maxRouteAuthorizationCost uint64 = 1_000_000_000

var routeAuthorizationDeviceIDPattern = regexp.MustCompile(`^wd_[a-z2-7]{16}$`)

type RouteAuthorizationRequest struct {
	SourceDeviceID      string
	RouterDeviceID      string
	DestinationDeviceID string
	FirstTransport      mesh.TransportName
	SecondTransport     mesh.TransportName
	FirstCost           uint64
	SecondCost          uint64
}

type routeAuthorizationResponse struct {
	Route         mesh.Route              `json:"route"`
	Authorization mesh.RouteAuthorization `json:"authorization"`
}

func (c Client) IssueRouteAuthorization(
	ctx context.Context,
	session *Session,
	request RouteAuthorizationRequest,
) (
	mesh.Route,
	mesh.RouteAuthorization,
	error,
) {
	if session == nil {
		return mesh.Route{},
			mesh.RouteAuthorization{},
			errors.New("account session is nil")
	}

	if err := session.validate(); err != nil {
		return mesh.Route{},
			mesh.RouteAuthorization{},
			fmt.Errorf(
				"invalid account session: %w",
				err,
			)
	}

	request = normalizeRouteAuthorizationRequest(request)

	if err := validateRouteAuthorizationRequest(request); err != nil {
		return mesh.Route{},
			mesh.RouteAuthorization{},
			err
	}

	var response routeAuthorizationResponse

	if err := c.doJSON(
		ctx,
		"POST",
		session.SupabaseURL+
			"/functions/v1/route-authorization",
		session.PublishableKey,
		session.AccessToken,
		map[string]any{
			"source_device_id":      request.SourceDeviceID,
			"router_device_id":      request.RouterDeviceID,
			"destination_device_id": request.DestinationDeviceID,
			"first_transport":       string(request.FirstTransport),
			"second_transport":      string(request.SecondTransport),
			"first_cost":            request.FirstCost,
			"second_cost":           request.SecondCost,
		},
		&response,
	); err != nil {
		return mesh.Route{},
			mesh.RouteAuthorization{},
			fmt.Errorf(
				"issue route authorization: %w",
				err,
			)
	}

	if err := validateRouteAuthorizationResponse(
		c.now().UTC(),
		request,
		response,
	); err != nil {
		return mesh.Route{},
			mesh.RouteAuthorization{},
			err
	}

	return response.Route,
		response.Authorization,
		nil
}

func normalizeRouteAuthorizationRequest(
	request RouteAuthorizationRequest,
) RouteAuthorizationRequest {
	request.SourceDeviceID =
		strings.TrimSpace(request.SourceDeviceID)

	request.RouterDeviceID =
		strings.TrimSpace(request.RouterDeviceID)

	request.DestinationDeviceID =
		strings.TrimSpace(request.DestinationDeviceID)

	request.FirstTransport =
		mesh.TransportName(
			strings.ToLower(
				strings.TrimSpace(
					string(request.FirstTransport),
				),
			),
		)

	request.SecondTransport =
		mesh.TransportName(
			strings.ToLower(
				strings.TrimSpace(
					string(request.SecondTransport),
				),
			),
		)

	return request
}

func validateRouteAuthorizationRequest(
	request RouteAuthorizationRequest,
) error {
	for name, id := range map[string]string{
		"source":      request.SourceDeviceID,
		"router":      request.RouterDeviceID,
		"destination": request.DestinationDeviceID,
	} {
		if !routeAuthorizationDeviceIDPattern.MatchString(id) {
			return fmt.Errorf(
				"invalid %s device ID",
				name,
			)
		}
	}

	if request.SourceDeviceID == request.RouterDeviceID ||
		request.SourceDeviceID == request.DestinationDeviceID ||
		request.RouterDeviceID == request.DestinationDeviceID {
		return errors.New(
			"source, router, and destination device IDs must differ",
		)
	}

	if !validRouteAuthorizationTransport(
		request.FirstTransport,
	) {
		return errors.New(
			"first routing transport must be lan or internet",
		)
	}

	if !validRouteAuthorizationTransport(
		request.SecondTransport,
	) {
		return errors.New(
			"second routing transport must be lan or internet",
		)
	}

	if request.FirstCost > maxRouteAuthorizationCost ||
		request.SecondCost > maxRouteAuthorizationCost {
		return errors.New(
			"route cost exceeds control-plane limit",
		)
	}

	return nil
}

func validRouteAuthorizationTransport(
	transport mesh.TransportName,
) bool {
	return transport == mesh.TransportLAN ||
		transport == mesh.TransportInternet
}

func validateRouteAuthorizationResponse(
	now time.Time,
	request RouteAuthorizationRequest,
	response routeAuthorizationResponse,
) error {
	route := response.Route

	if err := route.Validate(now); err != nil {
		return fmt.Errorf(
			"route authorization service returned invalid route: %w",
			err,
		)
	}

	if len(route.Hops) != 2 {
		return errors.New(
			"route authorization service returned a non-one-hop route",
		)
	}

	first := route.Hops[0]
	second := route.Hops[1]

	if route.Source !=
		mesh.DeviceID(request.SourceDeviceID) ||
		route.Destination !=
			mesh.DeviceID(request.DestinationDeviceID) ||
		first.From !=
			mesh.DeviceID(request.SourceDeviceID) ||
		first.To !=
			mesh.DeviceID(request.RouterDeviceID) ||
		first.Transport != request.FirstTransport ||
		first.Cost != request.FirstCost ||
		second.From !=
			mesh.DeviceID(request.RouterDeviceID) ||
		second.To !=
			mesh.DeviceID(request.DestinationDeviceID) ||
		second.Transport != request.SecondTransport ||
		second.Cost != request.SecondCost {
		return errors.New(
			"route authorization service returned a mismatched route",
		)
	}

	authorization := response.Authorization

	if strings.TrimSpace(authorization.KeyID) == "" ||
		len(authorization.KeyID) > 128 ||
		strings.ContainsAny(
			authorization.KeyID,
			"\r\n\t",
		) {
		return errors.New(
			"route authorization service returned an invalid key ID",
		)
	}

	signature, err :=
		base64.RawURLEncoding.DecodeString(
			authorization.Signature,
		)

	if err != nil ||
		len(signature) != ed25519.SignatureSize {
		return errors.New(
			"route authorization service returned an invalid signature",
		)
	}

	claims := authorization.Claims

	if claims.Version !=
		mesh.RouteAuthorizationVersion ||
		claims.Issuer !=
			mesh.RouteAuthorizationIssuer ||
		claims.Audience !=
			mesh.RouteAuthorizationAudience ||
		claims.Permission !=
			mesh.RouteAuthorizationPermission {
		return errors.New(
			"route authorization service returned an invalid capability profile",
		)
	}

	jti, err :=
		base64.RawURLEncoding.DecodeString(
			claims.JTI,
		)

	if err != nil || len(jti) != 16 {
		return errors.New(
			"route authorization service returned an invalid JTI",
		)
	}

	if claims.Router !=
		mesh.DeviceID(request.RouterDeviceID) {
		return errors.New(
			"route authorization service returned a mismatched router",
		)
	}

	if claims.IssuedAtUnixMS <= 0 ||
		claims.ExpiresUnixMS <=
			claims.IssuedAtUnixMS ||
		claims.ExpiresUnixMS-
			claims.IssuedAtUnixMS >
			mesh.MaxRouteAuthorizationLifetime.Milliseconds() ||
		claims.ExpiresUnixMS <= now.UnixMilli() {
		return errors.New(
			"route authorization service returned an invalid lifetime",
		)
	}

	if route.ExpiresAt.UTC().UnixMilli() !=
		claims.ExpiresUnixMS {
		return errors.New(
			"route authorization service returned mismatched expiry",
		)
	}

	if !routeAuthorizationRoutesEqual(
		route,
		claims.Route,
	) {
		return errors.New(
			"route authorization service returned mismatched signed route claims",
		)
	}

	return nil
}

func routeAuthorizationRoutesEqual(
	left mesh.Route,
	right mesh.Route,
) bool {
	if left.ID != right.ID ||
		left.Source != right.Source ||
		left.Destination != right.Destination ||
		left.ExpiresAt.UTC().UnixMilli() !=
			right.ExpiresAt.UTC().UnixMilli() ||
		len(left.Hops) != len(right.Hops) {
		return false
	}

	for index := range left.Hops {
		a := left.Hops[index]
		b := right.Hops[index]

		if a.From != b.From ||
			a.To != b.To ||
			a.Transport != b.Transport ||
			a.Cost != b.Cost {
			return false
		}
	}

	return true
}
