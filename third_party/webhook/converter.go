package webhook

// TODO: This whole converter is temporary.
import (
	authz "k8s.io/api/authorization/v1"
	authzv1beta1 "k8s.io/api/authorization/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getExtras(rV1Beta1 *authzv1beta1.SubjectAccessReview) map[string]authz.ExtraValue {
	v1Extra := make(map[string]authz.ExtraValue)
	if rV1Beta1 == nil || rV1Beta1.Spec.Extra == nil {
		return v1Extra
	}

	for key, value := range rV1Beta1.Spec.Extra {
		v1Extra[key] = authz.ExtraValue(value)
	}
	return v1Extra
}

func getNonResourceAttributes(rV1Beta1 *authzv1beta1.SubjectAccessReview) (nra *authz.NonResourceAttributes) {
	if rV1Beta1 == nil || rV1Beta1.Spec.NonResourceAttributes == nil {
		return nra
	}

	nra = &authz.NonResourceAttributes{
		Path: rV1Beta1.Spec.NonResourceAttributes.Path,
		Verb: rV1Beta1.Spec.NonResourceAttributes.Verb,
	}
	return nra
}

func getResourceAttributes(rV1Beta1 *authzv1beta1.SubjectAccessReview) (ra *authz.ResourceAttributes) {
	if rV1Beta1 == nil || rV1Beta1.Spec.ResourceAttributes == nil {
		return ra
	}

	ra = &authz.ResourceAttributes{
		Namespace:   rV1Beta1.Spec.ResourceAttributes.Namespace,
		Verb:        rV1Beta1.Spec.ResourceAttributes.Verb,
		Group:       rV1Beta1.Spec.ResourceAttributes.Group,
		Version:     rV1Beta1.Spec.ResourceAttributes.Version,
		Resource:    rV1Beta1.Spec.ResourceAttributes.Resource,
		Subresource: rV1Beta1.Spec.ResourceAttributes.Subresource,
		Name:        rV1Beta1.Spec.ResourceAttributes.Name,
	}
	return ra
}

func getSpec(rV1Beta1 *authzv1beta1.SubjectAccessReview) (spec authz.SubjectAccessReviewSpec) {
	if rV1Beta1 == nil {
		return spec
	}
	spec = authz.SubjectAccessReviewSpec{
		User:                  rV1Beta1.Spec.User,
		UID:                   rV1Beta1.Spec.UID,
		Extra:                 getExtras(rV1Beta1),
		Groups:                rV1Beta1.Spec.Groups,
		NonResourceAttributes: getNonResourceAttributes(rV1Beta1),
		ResourceAttributes:    getResourceAttributes(rV1Beta1),
	}
	return spec
}

func getStatus(rV1Beta1 *authzv1beta1.SubjectAccessReview) (status authz.SubjectAccessReviewStatus) {
	if rV1Beta1 == nil {
		return status
	}
	status = authz.SubjectAccessReviewStatus{
		Allowed:         rV1Beta1.Status.Allowed,
		Denied:          rV1Beta1.Status.Denied,
		Reason:          rV1Beta1.Status.Reason,
		EvaluationError: rV1Beta1.Status.EvaluationError,
	}
	return status
}

func getObjectMeta(rV1Beta1 *authzv1beta1.SubjectAccessReview) (om metav1.ObjectMeta) {
	if rV1Beta1 == nil {
		return om
	}
	om = *rV1Beta1.ObjectMeta.DeepCopy()
	return om
}

func ConvertIntoV1(rV1Beta1 authzv1beta1.SubjectAccessReview) authz.SubjectAccessReview {
	return authz.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       rV1Beta1.Kind,
			APIVersion: authzSupportedVersion,
		},
		ObjectMeta: getObjectMeta(&rV1Beta1),
		Spec:       getSpec(&rV1Beta1),
		Status:     getStatus(&rV1Beta1),
	}
}
