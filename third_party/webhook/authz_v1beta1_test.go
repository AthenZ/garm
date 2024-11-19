package webhook

import (
	"context"
	"errors"
	"testing"

	authz "k8s.io/api/authorization/v1"
	authzv1beta1 "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: Remove this file authz_v1beta1_test.go! This is a temporary test to ensure that the old API version is still supported & will be eventually removed.

// TODO: This is a temporary test to ensure that the old API version is still supported & will be eventually removed.

func tester(t *testing.T, input authzv1beta1.SubjectAccessReview) {
	s := newAuthzScaffold(t)
	defer s.Close()
	s.config.Mapper = mrfn(func(ctx context.Context, spec authz.SubjectAccessReviewSpec) (principal string, checks []AthenzAccessCheck, err error) {
		return "",
			nil,
			errors.New("foobar")
	})

	ar := runAuthzTest(s, serialize(input), nil)
	w := ar.w
	body := ar.body
	result := w.Result()

	if result.StatusCode != 200 {
		t.Fatal("invalid status code", result.StatusCode)
	}
	tr := checkGrant(t, body.Bytes(), false)

	if tr.APIVersion != authzSupportedBetaVersion {
		t.Errorf("wrong API version. Want '%s', got '%s'", authzSupportedBetaVersion, tr.APIVersion)
	}

	msg := "mapping error: foobar"
	if tr.Status.EvaluationError != msg {
		t.Errorf("want '%s', got '%s'", msg, tr.Status.EvaluationError)
	}
	if tr.Status.Reason != helpText {
		t.Error("authz internals leak")
	}
	s.containsLog(msg)
}

func stdAuthzBeta1Input(insertingGroup []string) authzv1beta1.SubjectAccessReview {
	return authzv1beta1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       authzSupportedKind,
			APIVersion: authzSupportedBetaVersion,
		},
		Spec: authzv1beta1.SubjectAccessReviewSpec{
			User: "bob",
			ResourceAttributes: &authzv1beta1.ResourceAttributes{
				Namespace: "foo-bar",
				Verb:      "get",
				Resource:  "baz",
			},
			Groups: insertingGroup,
		},
	}
}

// TODO: This is a temporary test to ensure that the old API version is still supported & will be eventually removed.
func TestAuthzBetaV1ApiConversion(t *testing.T) {
	insertingGroups := [][]string{
		{"v1beta1-testing", "v1beta1-group"}, // multiple elements
		{},                                   // empty group
		nil,                                  // not defined
	}

	for _, insertingGroup := range insertingGroups {
		tester(t, stdAuthzBeta1Input(insertingGroup))
	}
}
