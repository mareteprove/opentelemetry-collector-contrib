// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ottlfuncs // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/parseutils"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

type ParseKeyValueArguments[K any] struct {
	Target        ottl.StringGetter[K]
	Delimiter     ottl.Optional[string]
	PairDelimiter ottl.Optional[string]
	// IgnoreMalformedTokens (false by default) causes the parser
	// to ignore and skip string tokens (a token is a string
	// separated from other tokens by PairDelimiter) which cannot
	// be parses as a (non-empty) key and (non-empty) value, that
	// is string tokens which do not have exactly one Delimiter in
	// them, with non-empty strings on both sides of the
	// Delimiter. When set, such malformed tokens will be ignored
	// and not parsed for a key and value, while other tokens that
	// are well formed will still yield key-values without the
	// ParseKeyValue function returning any errors.
	IgnoreMalformedTokens ottl.Optional[bool]
}

func NewParseKeyValueFactory[K any]() ottl.Factory[K] {
	return ottl.NewFactory("ParseKeyValue", &ParseKeyValueArguments[K]{}, createParseKeyValueFunction[K])
}

func createParseKeyValueFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*ParseKeyValueArguments[K])

	if !ok {
		return nil, fmt.Errorf("ParseKeyValueFactory args must be of type *ParseKeyValueArguments[K]")
	}

	return parseKeyValue[K](args.Target, args.Delimiter, args.PairDelimiter, args.IgnoreMalformedTokens)
}

func parseKeyValue[K any](target ottl.StringGetter[K], d ottl.Optional[string], p ottl.Optional[string], ignoreMalformedTokens ottl.Optional[bool]) (ottl.ExprFunc[K], error) {
	delimiter := "="
	if !d.IsEmpty() {
		if d.Get() == "" {
			return nil, fmt.Errorf("delimiter cannot be set to an empty string")
		}
		delimiter = d.Get()
	}

	pairDelimiter := " "
	if !p.IsEmpty() {
		if p.Get() == "" {
			return nil, fmt.Errorf("pair delimiter cannot be set to an empty string")
		}
		pairDelimiter = p.Get()
	}

	if pairDelimiter == delimiter {
		return nil, fmt.Errorf("pair delimiter %q cannot be equal to delimiter %q", pairDelimiter, delimiter)
	}

	return func(ctx context.Context, tCtx K) (any, error) {
		source, err := target.Get(ctx, tCtx)
		if err != nil {
			return nil, err
		}

		if source == "" {
			return nil, fmt.Errorf("cannot parse from empty target")
		}

		pairs, err := parseutils.SplitString(source, pairDelimiter)
		if err != nil {
			return nil, fmt.Errorf("splitting source %q into pairs failed: %w", source, err)
		}

		imt := false
		if !ignoreMalformedTokens.IsEmpty() {
			imt = ignoreMalformedTokens.Get()
		}
		validPairs := make([]string, 0, len(pairs))
		if imt {
			for _, pv := range pairs {
				if n := strings.Count(pv, delimiter); n == 1 {
					if before, after, _ := strings.Cut(pv, delimiter); len(before) > 0 && len(after) > 0 {
						validPairs = append(validPairs, pv)
					}
				}
			}

			pairs = validPairs
		}

		parsed, err := parseutils.ParseKeyValuePairs(pairs, delimiter)
		if err != nil {
			return nil, fmt.Errorf("failed to split pairs into key-values: %w", err)
		}

		result := pcommon.NewMap()
		err = result.FromRaw(parsed)
		return result, err
	}, nil
}
