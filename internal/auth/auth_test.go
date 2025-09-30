package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		wantKey       string
		wantErrString string
	}{
		{
			name:       "valid ApiKey header",
			authHeader: "ApiKey my-secret-key",
			wantKey:    "my-secret-key",
		},
		{
			name:          "missing header",
			authHeader:    "",
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:          "wrong prefix",
			authHeader:    "Bearer sometoken",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if tt.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrString)
				}
				if err.Error() != tt.wantErrString {
					t.Errorf("expected error %q, got %q", tt.wantErrString, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if gotKey != tt.wantKey {
					t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
				}
			}
		})
	}
}
