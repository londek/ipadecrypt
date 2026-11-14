package device

import (
	"errors"
	"testing"
)

func TestClassifyAuthenticationError(t *testing.T) {
	err := classifyAuthenticationError(errors.New("ssh: unable to authenticate"))
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error %v does not match ErrAuthentication", err)
	}

	other := errors.New("connection refused")
	if got := classifyAuthenticationError(other); got != other {
		t.Fatalf("unrelated error changed to %v", got)
	}
}

func TestPasswordAnswers(t *testing.T) {
	challenge := passwordAnswers("secret")

	answers, err := challenge("mobile", "", []string{"Password:", "Verification code:"}, []bool{false, false})
	if err != nil {
		t.Fatal(err)
	}

	if len(answers) != 2 || answers[0] != "secret" || answers[1] != "secret" {
		t.Fatalf("unexpected answers: %#v", answers)
	}
}
