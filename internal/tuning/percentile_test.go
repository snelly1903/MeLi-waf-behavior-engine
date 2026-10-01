// Prueba el resumen de percentiles.
package tuning

import "testing"

func TestSummarize_HandComputed(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	s := Summarize(values)

	if s.N != 10 {
		t.Errorf("N = %d, want 10", s.N)
	}
	if s.Min != 1 {
		t.Errorf("Min = %v, want 1", s.Min)
	}
	if s.Max != 10 {
		t.Errorf("Max = %v, want 10", s.Max)
	}
	if s.P50 != 5 {
		t.Errorf("P50 = %v, want 5", s.P50)
	}
	if s.P75 != 8 {
		t.Errorf("P75 = %v, want 8", s.P75)
	}
	if s.P90 != 9 {
		t.Errorf("P90 = %v, want 9", s.P90)
	}
	if s.P95 != 10 {
		t.Errorf("P95 = %v, want 10", s.P95)
	}
}

func TestSummarize_Empty_ReturnsZeroN(t *testing.T) {
	s := Summarize(nil)
	if s.N != 0 {
		t.Errorf("N = %d, want 0", s.N)
	}
}

func TestSummarize_UnsortedInput_SameResultAsSorted(t *testing.T) {
	a := Summarize([]float64{5, 1, 9, 3, 7, 2, 8, 4, 10, 6})
	b := Summarize([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	if a != b {
		t.Errorf("Summarize dependió del orden de entrada: %+v vs %+v", a, b)
	}
}
