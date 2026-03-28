package ctl

import "testing"

func TestTableHeight(t *testing.T) {
	tests := []struct {
		height int
		want   int
	}{
		{0, 15},  // zero → fallback
		{24, 15}, // 24-9 = 15, standard 24-line terminal
		{40, 31}, // 40-9 = 31
		{11, 3},  // 11-9 = 2, clamped to minimum
		{12, 3},  // 12-9 = 3, exactly at minimum
		{13, 4},  // 13-9 = 4, just above minimum
	}
	for _, tt := range tests {
		m := model{height: tt.height}
		if got := m.tableHeight(); got != tt.want {
			t.Errorf("tableHeight() with height=%d = %d, want %d", tt.height, got, tt.want)
		}
	}
}

func TestPickerHeight(t *testing.T) {
	tests := []struct {
		height int
		want   int
	}{
		{0, 9},   // zero → fallback
		{24, 19}, // 24-5 = 19
		{40, 35}, // 40-5 = 35
		{12, 8},  // 12-5 = 7, clamped to minimum
		{13, 8},  // 13-5 = 8, exactly at minimum
		{14, 9},  // 14-5 = 9, just above minimum
	}
	for _, tt := range tests {
		m := model{height: tt.height}
		if got := m.pickerHeight(); got != tt.want {
			t.Errorf("pickerHeight() with height=%d = %d, want %d", tt.height, got, tt.want)
		}
	}
}
