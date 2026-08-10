package handlers

// White-box tests for readingTime — a pure helper used by GetPost, which
// otherwise requires a live DB to exercise.

import "testing"

func TestReadingTime_EmptyBody_ReturnsMinimumOneMinute(t *testing.T) {
	if got := readingTime(""); got != 1 {
		t.Errorf("expected minimum 1 minute for empty body, got %d", got)
	}
}

func TestReadingTime_ShortBody_ReturnsMinimumOneMinute(t *testing.T) {
	if got := readingTime("just a few words here"); got != 1 {
		t.Errorf("expected minimum 1 minute for a short body, got %d", got)
	}
}

func TestReadingTime_ExactlyAtWordsPerMinuteBoundary(t *testing.T) {
	// 200 words / 200 wpm = 1 (integer division), still floors to the
	// documented minimum of 1 rather than 0.
	body := repeatWord("word", 200)
	if got := readingTime(body); got != 1 {
		t.Errorf("expected 1 minute for exactly 200 words, got %d", got)
	}
}

func TestReadingTime_400Words_Returns2Minutes(t *testing.T) {
	body := repeatWord("word", 400)
	if got := readingTime(body); got != 2 {
		t.Errorf("expected 2 minutes for 400 words, got %d", got)
	}
}

func TestReadingTime_1000Words_Returns5Minutes(t *testing.T) {
	body := repeatWord("word", 1000)
	if got := readingTime(body); got != 5 {
		t.Errorf("expected 5 minutes for 1000 words, got %d", got)
	}
}

func repeatWord(word string, n int) string {
	s := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			s += " "
		}
		s += word
	}
	return s
}
