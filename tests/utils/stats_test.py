# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/stats.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/stats_test.py
"""

from __future__ import annotations

import math

import pytest

from transcrypto.utils import base, stats


def test_measurement_stats_failures() -> None:
  """Tests."""
  # no data
  with pytest.raises(base.InputError, match='no data'):
    stats.MeasurementStats([])
  # invalid confidence
  with pytest.raises(base.InputError, match='invalid confidence'):
    stats.MeasurementStats([1, 2, 3], confidence=0.0)
  with pytest.raises(base.InputError, match='invalid confidence'):
    stats.MeasurementStats([1, 2, 3], confidence=1.1)


@pytest.mark.parametrize(
  ('z', 'expected'),
  [
    # Γ(1) = 0! = 1
    (1.0, 1.0),
    # Γ(2) = 1! = 1
    (2.0, 1.0),
    # Γ(3) = 2! = 2
    (3.0, 2.0),
    # Γ(4) = 3! = 6
    (4.0, 6.0),
    # Γ(5) = 4! = 24
    (5.0, 24.0),
    # Γ(6) = 5! = 120
    (6.0, 120.0),
    # Γ(10) = 9! = 362880
    (10.0, 362880.0),
    # Γ(0.5) = √π
    (0.5, math.sqrt(math.pi)),
    # Γ(1.5) = √π/2
    (1.5, math.sqrt(math.pi) / 2.0),
    # Γ(2.5) = 3√π/4
    (2.5, 3.0 * math.sqrt(math.pi) / 4.0),
    # Γ(3.5) = 15√π/8
    (3.5, 15.0 * math.sqrt(math.pi) / 8.0),
    # negative values using reflection formula
    (-0.5, -2.0 * math.sqrt(math.pi)),
    (-1.5, 4.0 * math.sqrt(math.pi) / 3.0),
  ],
)
def test_GammaLanczos_known_values(z: float, expected: float) -> None:
  """Test _GammaLanczos against known gamma function values."""
  result: float = stats.GammaLanczos(z)
  assert math.isclose(result, expected, rel_tol=1e-10), f'Γ({z}) = {result}, expected {expected}'


@pytest.mark.parametrize(
  'z',
  [0.1, 0.25, 0.75, 1.0, 1.5, 2.0, 2.5, 3.0, 4.5, 5.5, 7.0, 10.0, 15.0],
)
def test_GammaLanczos_matches_math_gamma(z: float) -> None:
  """Test _GammaLanczos matches stdlib math.gamma for positive values."""
  result: float = stats.GammaLanczos(z)
  expected: float = math.gamma(z)
  assert math.isclose(result, expected, rel_tol=1e-10), f'Γ({z}): got {result}, expected {expected}'


@pytest.mark.parametrize(
  ('a', 'b', 'x', 'expected'),
  [
    # I_0(a, b) = 0 for any a, b
    (1.0, 1.0, 0.0, 0.0),
    (2.0, 3.0, 0.0, 0.0),
    (0.5, 0.5, 0.0, 0.0),
    # I_1(a, b) = 1 for any a, b
    (1.0, 1.0, 1.0, 1.0),
    (2.0, 3.0, 1.0, 1.0),
    (5.0, 2.0, 1.0, 1.0),
    # I_x(1, 1) = x (uniform distribution CDF)
    (1.0, 1.0, 0.25, 0.25),
    (1.0, 1.0, 0.5, 0.5),
    (1.0, 1.0, 0.75, 0.75),
    # I_0.5(1, 1) = 0.5 (symmetric case)
    (2.0, 2.0, 0.5, 0.5),
    (3.0, 3.0, 0.5, 0.5),
    # Known values from beta function tables
    (2.0, 5.0, 0.4, 0.76672),
    (3.0, 2.0, 0.3, 0.08370),
    (0.5, 0.5, 0.5, 0.5),  # arcsine distribution
  ],
)
def test_BetaIncomplete_known_values(a: float, b: float, x: float, expected: float) -> None:
  """Test _BetaIncomplete against known incomplete beta values."""
  result: float = stats.BetaIncomplete(a, b, x)
  assert math.isclose(result, expected, rel_tol=1e-4), f'I_{x}({a},{b}) = {result}, exp {expected}'


def test_BetaIncomplete_invalid_x() -> None:
  """Test _BetaIncomplete raises error for x outside [0, 1]."""
  with pytest.raises(base.InputError, match='x must be in'):
    stats.BetaIncomplete(1.0, 1.0, -0.1)
  with pytest.raises(base.InputError, match='x must be in'):
    stats.BetaIncomplete(1.0, 1.0, 1.5)


@pytest.mark.parametrize(
  ('a', 'b', 'x'),
  [
    # Edge cases that trigger the tiny value protection branches in continued fraction
    # Very small x with large a and b can trigger underflow protection
    (100.0, 100.0, 0.001),
    (50.0, 50.0, 0.999),
    # Extreme parameter combinations
    (0.01, 0.01, 0.5),
    (100.0, 0.1, 0.99),
    (0.1, 100.0, 0.01),
    # Values near the switchover point (a+1)/(a+b+2)
    (2.0, 3.0, 0.428),  # close to (2+1)/(2+3+2) = 3/7 ≈ 0.4286
    (5.0, 5.0, 0.55),  # close to (5+1)/(5+5+2) = 0.5
  ],
)
def test_BetaIncompleteCF_edge_cases(a: float, b: float, x: float) -> None:
  """Test _BetaIncomplete with edge cases that exercise underflow protection."""
  result: float = stats.BetaIncomplete(a, b, x)
  # Just verify it returns a valid probability
  assert 0.0 <= result <= 1.0, f'I_{x}({a},{b}) = {result} out of bounds'
  # Verify consistency with symmetry property
  result_sym: float = stats.BetaIncomplete(b, a, 1.0 - x)
  assert math.isclose(result + result_sym, 1.0, rel_tol=1e-6)


@pytest.mark.parametrize(
  ('a', 'b', 'x'),
  [
    # Test symmetry: I_x(a, b) + I_(1-x)(b, a) = 1
    (2.0, 3.0, 0.3),
    (1.5, 2.5, 0.4),
    (5.0, 2.0, 0.7),
    (0.5, 0.5, 0.25),
    (3.0, 1.0, 0.6),
  ],
)
def test_BetaIncomplete_symmetry(a: float, b: float, x: float) -> None:
  """Test _BetaIncomplete symmetry property: I_x(a,b) + I_(1-x)(b,a) = 1."""
  result1: float = stats.BetaIncomplete(a, b, x)
  result2: float = stats.BetaIncomplete(b, a, 1.0 - x)
  assert math.isclose(result1 + result2, 1.0, rel_tol=1e-10)


@pytest.mark.parametrize(
  ('t_val', 'df', 'expected'),
  [
    # t=0 always gives CDF=0.5 (symmetric distribution)
    (0.0, 1, 0.5),
    (0.0, 5, 0.5),
    (0.0, 10, 0.5),
    (0.0, 100, 0.5),
    # Known t-distribution CDF values from statistical tables for df=1 (Cauchy)
    (1.0, 1, 0.75),
    (-1.0, 1, 0.25),
    # Large df approaches normal distribution
    (1.96, 1000, 0.975),  # ~97.5% for large df
    (-1.96, 1000, 0.025),  # ~2.5%
    # CDF values for df=5
    (2.015, 5, 0.95),  # approx 95th percentile
    (-2.015, 5, 0.05),  # approx 5th percentile
    # CDF value for df=10
    (1.812, 10, 0.95),  # approx 95th percentile
  ],
)
def test_StudentTCDF_known_values(t_val: float, df: int, expected: float) -> None:
  """Test _StudentTCDF against known t-distribution CDF values."""
  result: float = stats.StudentTCDF(t_val, df)
  assert math.isclose(result, expected, rel_tol=0.01), (
    f'CDF({t_val}, {df}) = {result}, exp {expected}'
  )


@pytest.mark.parametrize(
  'df',
  [1, 2, 3, 5, 10, 20, 50, 100],
)
def test_StudentTCDF_symmetry(df: int) -> None:
  """Test _StudentTCDF symmetry: CDF(-t) = 1 - CDF(t)."""
  for t_val in [0.5, 1.0, 1.5, 2.0, 3.0]:
    cdf_pos: float = stats.StudentTCDF(t_val, df)
    cdf_neg: float = stats.StudentTCDF(-t_val, df)
    assert math.isclose(cdf_pos + cdf_neg, 1.0, rel_tol=1e-10)


@pytest.mark.parametrize(
  'df',
  [1, 2, 5, 10, 30, 100],
)
def test_StudentTCDF_monotonic(df: int) -> None:
  """Test _StudentTCDF is monotonically increasing."""
  t_values: list[float] = [-3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0]
  cdf_values: list[float] = [stats.StudentTCDF(t, df) for t in t_values]
  for i in range(len(cdf_values) - 1):
    assert cdf_values[i] < cdf_values[i + 1], f'CDF not monotonic at df={df}'


@pytest.mark.parametrize(
  'df',
  [1, 2, 5, 10, 30, 100],
)
def test_StudentTCDF_bounds(df: int) -> None:
  """Test _StudentTCDF returns values in [0, 1]."""
  for t_val in [-100, -10, -1, 0, 1, 10, 100]:
    cdf: float = stats.StudentTCDF(t_val, df)
    assert 0.0 <= cdf <= 1.0, f'CDF({t_val}, {df}) = {cdf} out of bounds'


@pytest.mark.parametrize(
  ('q', 'df', 'expected'),
  [
    # q=0.5 always gives t=0 (symmetric)
    (0.5, 1, 0.0),
    (0.5, 5, 0.0),
    (0.5, 10, 0.0),
    (0.5, 100, 0.0),
    # Known critical t-values from statistical tables for df=1 (Cauchy distribution)
    (0.75, 1, 1.0),
    (0.25, 1, -1.0),
    (0.95, 1, 6.314),
    (0.975, 1, 12.706),
    # Critical t-values for df=5
    (0.95, 5, 2.015),
    (0.975, 5, 2.571),
    (0.05, 5, -2.015),
    # Critical t-values for df=10
    (0.95, 10, 1.812),
    (0.975, 10, 2.228),
    # Critical t-values for df=30
    (0.95, 30, 1.697),
    (0.975, 30, 2.042),
    # Large df approaches normal distribution (z ≈ 1.96 for 97.5%)
    (0.975, 1000, 1.962),
  ],
)
def test_StudentTPPF_known_values(q: float, df: int, expected: float) -> None:
  """Test _StudentTPPF against known t-distribution quantiles."""
  result: float = stats.StudentTPPF(q, df)
  assert math.isclose(result, expected, rel_tol=0.01), f'PPF({q}, {df}) = {result}, exp {expected}'


def test_StudentTPPF_invalid_q() -> None:
  """Test _StudentTPPF raises error for q outside (0, 1)."""
  with pytest.raises(base.InputError, match='q must be in'):
    stats.StudentTPPF(0.0, 10)
  with pytest.raises(base.InputError, match='q must be in'):
    stats.StudentTPPF(1.0, 10)
  with pytest.raises(base.InputError, match='q must be in'):
    stats.StudentTPPF(-0.5, 10)
  with pytest.raises(base.InputError, match='q must be in'):
    stats.StudentTPPF(1.5, 10)


@pytest.mark.parametrize(
  'df',
  [1, 2, 5, 10, 30, 100],
)
def test_StudentTPPF_symmetry(df: int) -> None:
  """Test _StudentTPPF symmetry: PPF(q) = -PPF(1-q)."""
  for q in [0.1, 0.25, 0.4, 0.6, 0.75, 0.9]:
    ppf_q: float = stats.StudentTPPF(q, df)
    ppf_1mq: float = stats.StudentTPPF(1.0 - q, df)
    assert math.isclose(ppf_q, -ppf_1mq, rel_tol=1e-8), f'PPF symmetry failed for q={q}, df={df}'


@pytest.mark.parametrize(
  ('df', 'q'),
  [
    (1, 0.1),
    (1, 0.5),
    (1, 0.9),
    (5, 0.05),
    (5, 0.5),
    (5, 0.95),
    (10, 0.025),
    (10, 0.5),
    (10, 0.975),
    (30, 0.01),
    (30, 0.99),
    (100, 0.001),
    (100, 0.999),
  ],
)
def test_StudentTPPF_CDF_inverse(df: int, q: float) -> None:
  """Test _StudentTPPF is the inverse of _StudentTCDF: CDF(PPF(q)) ≈ q."""
  t_val: float = stats.StudentTPPF(q, df)
  cdf_val: float = stats.StudentTCDF(t_val, df)
  assert math.isclose(cdf_val, q, rel_tol=1e-8), f'CDF(PPF({q})) = {cdf_val} ≠ {q} for df={df}'


@pytest.mark.parametrize(
  'df',
  [1, 2, 5, 10, 30, 100],
)
def test_StudentTPPF_monotonic(df: int) -> None:
  """Test _StudentTPPF is monotonically increasing."""
  q_values: list[float] = [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99]
  ppf_values: list[float] = [stats.StudentTPPF(q, df) for q in q_values]
  for i in range(len(ppf_values) - 1):
    assert ppf_values[i] < ppf_values[i + 1], f'PPF not monotonic at df={df}'


@pytest.mark.parametrize(
  ('data', 'expected_mean', 'expected_variance'),
  [
    # Simple cases
    ([1, 2, 3], 2.0, 1.0),  # Var = [(1-2)² + (2-2)² + (3-2)²] / 2 = 2/2 = 1
    ([1, 1, 1], 1.0, 0.0),  # No variance
    ([0, 10], 5.0, 50.0),  # Var = [(0-5)² + (10-5)²] / 1 = 50
    # Larger sample
    ([1, 2, 3, 4, 5], 3.0, 2.5),  # Var = 10/4 = 2.5
    # Floats
    ([1.5, 2.5, 3.5], 2.5, 1.0),
    # Negative values
    ([-1, 0, 1], 0.0, 1.0),
    ([-3, -2, -1], -2.0, 1.0),
  ],
)
def test_SampleVariance(data: list[float], expected_mean: float, expected_variance: float) -> None:
  """Test _SampleVariance computes correct sample variance with Bessel's correction."""
  result: float = stats.SampleVariance(data, expected_mean)
  assert math.isclose(result, expected_variance, rel_tol=1e-10)


@pytest.mark.parametrize(('data', 'mean'), [([], 0.0), ([1], 1.0)])
def test_SampleVariance_failures(data: list[float], mean: float) -> None:
  """Test SampleVariance raises InputError for insufficient data points."""
  with pytest.raises(base.InputError):
    stats.SampleVariance(data, mean)


@pytest.mark.parametrize(
  ('data', 'expected_mean', 'expected_sem'),
  [
    # Simple cases: SEM = sqrt(Var/n) = sqrt(s²/n)
    ([1, 2, 3], 2.0, math.sqrt(1.0 / 3)),  # s²=1, n=3
    ([1, 1, 1], 1.0, 0.0),  # No variance → SEM=0
    ([0, 10], 5.0, math.sqrt(50.0 / 2)),  # s²=50, n=2
    # Larger sample
    ([1, 2, 3, 4, 5], 3.0, math.sqrt(2.5 / 5)),  # s²=2.5, n=5
    # Floats
    ([1.5, 2.5, 3.5], 2.5, math.sqrt(1.0 / 3)),
  ],
)
def test_StandardErrorOfMean(data: list[float], expected_mean: float, expected_sem: float) -> None:
  """Test _StandardErrorOfMean computes correct mean and SEM."""
  mean: float
  sem: float
  mean, sem = stats.StandardErrorOfMean(data)
  assert math.isclose(mean, expected_mean, rel_tol=1e-10)
  assert math.isclose(sem, expected_sem, rel_tol=1e-10)


@pytest.mark.parametrize(
  ('confidence', 'df', 'loc', 'scale'),
  [
    (0.95, 9, 10.0, 1.0),  # standard case
    (0.99, 29, 0.0, 2.5),  # high confidence, more df
    (0.90, 4, -5.0, 0.5),  # lower confidence, few df
    (0.95, 1, 100.0, 10.0),  # df=1 (Cauchy-like tails)
    (0.95, 100, 0.0, 1.0),  # large df
  ],
)
def test_StudentTInterval_symmetric(confidence: float, df: int, loc: float, scale: float) -> None:
  """Test _StudentTInterval produces symmetric interval around loc."""
  lower: float
  upper: float
  lower, upper = stats.StudentTInterval(confidence, df, loc, scale)
  # Check symmetry
  assert math.isclose(upper - loc, loc - lower, rel_tol=1e-10)
  # Check loc is inside interval
  assert lower < loc < upper


@pytest.mark.parametrize(
  ('confidence', 'df', 'loc', 'scale', 'expected_half_width'),
  [
    # Half-width = t_crit * scale
    # df=∞ → t_crit(0.975) ≈ 1.96
    (0.95, 1000, 0.0, 1.0, 1.962),
    # df=10 → t_crit(0.975) ≈ 2.228
    (0.95, 10, 0.0, 1.0, 2.228),
    # df=5 → t_crit(0.975) ≈ 2.571
    (0.95, 5, 0.0, 1.0, 2.571),
    # Scaled
    (0.95, 10, 50.0, 2.0, 4.456),  # 2.228 * 2
  ],
)
def test_StudentTInterval_width(
  confidence: float, df: int, loc: float, scale: float, expected_half_width: float
) -> None:
  """Test _StudentTInterval produces correct interval width."""
  lower: float
  upper: float
  lower, upper = stats.StudentTInterval(confidence, df, loc, scale)
  half_width: float = (upper - lower) / 2.0
  assert math.isclose(half_width, expected_half_width, rel_tol=0.01)


@pytest.mark.parametrize(
  ('confidence1', 'confidence2', 'df'),
  [
    (0.90, 0.95, 10),
    (0.95, 0.99, 10),
    (0.90, 0.99, 30),
  ],
)
def test_StudentTInterval_higher_confidence_wider(
  confidence1: float, confidence2: float, df: int
) -> None:
  """Test higher confidence produces wider interval."""
  lower1, upper1 = stats.StudentTInterval(confidence1, df, 0.0, 1.0)
  lower2, upper2 = stats.StudentTInterval(confidence2, df, 0.0, 1.0)
  width1: float = upper1 - lower1
  width2: float = upper2 - lower2
  assert width1 < width2, f'{confidence1} CI should be narrower than {confidence2} CI'


@pytest.mark.parametrize(
  ('data', 'confidence'),
  [
    ([42], 0.95),  # trivial one-sample case
    ([1, 2, 3], 0.95),  # small sample
    ([1.0, 1.5, 2.0, 2.5], 0.99),  # floats + higher confidence
  ],
)
def test_measurement_stats_success(data: list[int | float], confidence: float) -> None:
  """Tests."""
  n: int
  mean: float
  sem: float
  error: float
  ci: tuple[float, float]
  conf: float
  n, mean, sem, error, ci, conf = stats.MeasurementStats(data, confidence=confidence)
  assert math.isclose(conf, confidence, rel_tol=1e-12)
  assert n == len(data)
  if n == 1:
    # For single sample, SEM/error = inf, CI = (-inf, inf)
    assert sem == math.inf
    assert error == math.inf
    assert ci[0] == -math.inf and ci[1] == math.inf
  else:
    # For multi-sample, finite numbers
    assert math.isfinite(mean)
    assert math.isfinite(sem)
    assert math.isfinite(error)
    assert ci[0] <= mean <= ci[1]
