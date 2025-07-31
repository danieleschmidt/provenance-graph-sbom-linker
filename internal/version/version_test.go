package version

import (
	"testing"
)

func TestGetVersion(t *testing.T) {
	version := GetVersion()
	if version == "" {
		t.Error("Version should not be empty")
	}
}

func TestGetCommit(t *testing.T) {
	commit := GetCommit()
	if commit == "" {
		t.Error("Commit should not be empty")
	}
}

func TestGetBuildDate(t *testing.T) {
	date := GetBuildDate()
	if date == "" {
		t.Error("Build date should not be empty")
	}
}