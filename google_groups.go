package jwtauth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
)

func googleDirectoryService(ctx context.Context, config *jwtConfig) (*admin.Service, error) {
	if config == nil {
		return nil, errors.New("missing config")
	}
	// TODO: Handle unconfigured service account

	jwtConfig, err := google.JWTConfigFromJSON([]byte(config.GoogleDirectoryServiceAccountKey), admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}
	jwtConfig.Subject = config.GoogleDirectoryImpersonateUser

	client := jwtConfig.Client(ctx)

	srv, err := admin.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create directory service %v", err)
	}
	return srv, nil
}

func googleGroupsPerUser(ctx context.Context, config *jwtConfig, userKey string) (groups []*admin.Group, err error) {
	// skip groups check if service account is not configured
	if len(config.GoogleDirectoryImpersonateUser) == 0 || len(config.GoogleDirectoryServiceAccountKey) == 0 {
		return []*admin.Group{}, nil
	}

	svc, err := googleDirectoryService(ctx, config)
	if err != nil {
		return []*admin.Group{}, err
	}

	query := svc.Groups.List().UserKey(userKey)

	for {
		resp, err := query.Do()
		if err != nil {
			return []*admin.Group{}, err
		}
		groups = append(groups, resp.Groups...)

		if resp.NextPageToken == "" {
			break
		}
		query.PageToken(resp.NextPageToken)
	}

	return groups, nil
}
