package jwtauth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"

	log "github.com/hashicorp/go-hclog"
	"github.com/mitchellh/pointerstructure"
)

// getClaim returns a claim value from allClaims given a provided claim string.
// If this string is a valid JSONPointer, it will be interpreted as such to locate
// the claim. Otherwise, the claim string will be used directly.
func getClaim(logger log.Logger, allClaims map[string]interface{}, claim string) interface{} {
	var val interface{}
	var err error

	if !strings.HasPrefix(claim, "/") {
		val = allClaims[claim]
	} else {
		val, err = pointerstructure.Get(allClaims, claim)
		if err != nil {
			logger.Warn(fmt.Sprintf("unable to locate %s in claims: %s", claim, err.Error()))
			return nil
		}
	}

	// The claims unmarshalled by go-oidc don't use UseNumber, so there will
	// be mismatches if they're coming in as float64 since Vault's config will
	// be represented as json.Number. If the operator can coerce claims data to
	// be in string form, there is no problem. Alternatively, we could try to
	// intelligently convert float64 to json.Number, e.g.:
	//
	// switch v := val.(type) {
	// case float64:
	// 	val = json.Number(strconv.Itoa(int(v)))
	// }
	//
	// Or we fork and/or PR go-oidc.

	return val
}

// extractMetadata builds a metadata map from a set of claims and claims mappings.
// The referenced claims must be strings and the claims mappings must be of the structure:
//
//   {
//       "/some/claim/pointer": "metadata_key1",
//       "another_claim": "metadata_key2",
//        ...
//   }
func extractMetadata(logger log.Logger, allClaims map[string]interface{}, claimMappings map[string]string) (map[string]string, error) {
	metadata := make(map[string]string)
	for source, target := range claimMappings {
		if value := getClaim(logger, allClaims, source); value != nil {
			strValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("error converting claim '%s' to string", source)
			}

			metadata[target] = strValue
		}
	}
	return metadata, nil
}

// validateAudience checks whether any of the audiences in audClaim match those
// in boundAudiences. If strict is true and there are no bound audiences, then the
// presence of any audience in the received claim is considered an error.
func validateAudience(boundAudiences, audClaim []string, strict bool) error {
	if strict && len(boundAudiences) == 0 && len(audClaim) > 0 {
		return errors.New("audience claim found in JWT but no audiences bound to the role")
	}

	if len(boundAudiences) > 0 {
		for _, v := range boundAudiences {
			if strutil.StrListContains(audClaim, v) {
				return nil
			}
		}
		return errors.New("aud claim does not match any bound audience")
	}

	return nil
}

// validateBoundClaims checks that all of the claim:value requirements in boundClaims are
// met in allClaims.
func validateBoundClaims(logger log.Logger, boundClaims, allClaims map[string]interface{}) error {
	for claim, expValue := range boundClaims {
		actValue := getClaim(logger, allClaims, claim)
		if actValue == nil {
			return fmt.Errorf("claim %q is missing", claim)
		}

		if expValue != actValue {
			return fmt.Errorf("claim %q does not match associated bound claim", claim)
		}
	}

	return nil
}

// validateGroups checks whether all of the groups in BoundGroups are contained in the group aliases
func validateGroups(boundGroups []string, groupAliases []*logical.Alias) error {
	// no groups bound
	if len(boundGroups) == 0 {
		return nil
	}

	groupFound := make(map[string]bool)

	// set groups
	for _, group := range boundGroups {
		groupFound[group] = false
	}

	// loop over aliases
	for _, groupAlias := range groupAliases {
		if _, ok := groupFound[groupAlias.Name]; ok {
			groupFound[groupAlias.Name] = true
		}
	}

	var groupsMissing []string
	for key, value := range groupFound {
		if !value {
			groupsMissing = append(groupsMissing, key)
		}
	}

	if len(groupsMissing) > 0 {
		return fmt.Errorf("missing group membership for %s", strings.Join(groupsMissing, ", "))
	}

	return nil
}
