package webhook

import (
	"strings"
	"webhook-server/configstruct"
	"webhook-server/loghub"

	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GlobalSidecarImage string

// check admitted pods
func UserDeny(ar v1.AdmissionReview) *v1.AdmissionResponse {
	loghub.Out(3, "Path /user-deny called", false)

	user := ar.Request.UserInfo
	convAction := "none"
	switch ar.Request.Operation {
	case "CREATE":
		convAction = "CREATE"
	case "DELETE":
		convAction = "DELETE"
	case "CONNECT":
		convAction = "CONNECT"
	case "UPDATE":
		convAction = "UPDATE"
	default:
		convAction = "unknown"
	}
	loghub.Out(0, "[AUDIT] User "+user.Username+" tried to "+convAction+" "+ar.Request.RequestKind.Kind, false)
	hit := false
	for _, name := range configstruct.CurrentConfig.WebhookServer.Security.AllowedAccounts {
		if name == user.Username {
			hit = true
		}
	}

	//initial response object
	reviewResponse := v1.AdmissionResponse{}
	reviewResponse.Allowed = false //deny the request
	reviewResponse.Result = &metav1.Status{Message: strings.TrimSpace("User " + user.Username + " is not allowed to do this!")}

	if hit {
		reviewResponse.Allowed = true
		reviewResponse.Result = &metav1.Status{Message: strings.TrimSpace("User " + user.Username + " is allowed to do this!")}
	}

	return &reviewResponse
}

func Audit(ar v1.AdmissionReview) *v1.AdmissionResponse {
	loghub.Out(3, "Path /user-audit called", false)

	user := ar.Request.UserInfo
	convAction := "none"
	switch ar.Request.Operation {
	case "CREATE":
		convAction = "CREATE"
	case "DELETE":
		convAction = "DELETE"
	case "CONNECT":
		convAction = "CONNECT"
	case "UPDATE":
		convAction = "UPDATE"
	default:
		convAction = "unknown"
	}
	loghub.Out(0, "[AUDIT] User "+user.Username+" tried to "+convAction+" "+ar.Request.RequestKind.Kind, false)

	//initial response object
	reviewResponse := v1.AdmissionResponse{}

	reviewResponse.Allowed = true //deny the request
	reviewResponse.Result = &metav1.Status{Message: strings.TrimSpace("You successfully triggered the webhook!")}

	return &reviewResponse
}
