# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto basic statistics library."""

from __future__ import annotations

import math
from collections import abc

from transcrypto.utils import base

# Lanczos coefficients for g=7, n=9; provides ~15 digit accuracy for gamma
_LANCZOS_G = 7
_LANCZOS_COEFF: tuple[float, ...] = (
  0.99999999999980993,
  676.5203681218851,
  -1259.1392167224028,
  771.32342877765313,
  -176.61502916214059,
  12.507343278686905,
  -0.13857109526572012,
  9.9843695780195716e-6,
  1.5056327351493116e-7,
)
_TINY: float = 1e-30
_NSG: abc.Callable[[float], float] = (
  lambda z: _TINY if abs(z) < _TINY else z  # numerical stability guard
)
_BETA_INCOMPLETE_MAX_ITER: int = 200
_BETA_INCOMPLETE_TOL: float = 1e-14
_STUDENT_SMALL: float = 1e-12


def GammaLanczos(z: float, /) -> float:
  """Compute the gamma function Γ(z) using the Lanczos approximation.

  The Lanczos approximation provides an efficient method to compute
  the gamma function with high accuracy (~15 digits). It uses the
  reflection formula for z < 0.5.

  Args:
    z (float): Input value. For z ≤ 0 where z is a non-positive integer,
      the function will return ±inf.

  Returns:
    float: Γ(z), the gamma function evaluated at z.

  Notes:
    - Uses coefficients optimized for g=7, n=9.
    - For z < 0.5, uses the reflection formula:
        Γ(z) = π / (sin(πz) · Γ(1-z))

  """
  if z < 0.5:  # noqa: PLR2004
    # Reflection formula: Γ(z) = π / (sin(πz) Γ(1-z))
    return math.pi / (math.sin(math.pi * z) * GammaLanczos(1.0 - z))
  z -= 1.0
  x: float = _LANCZOS_COEFF[0]
  for i in range(1, len(_LANCZOS_COEFF)):
    x += _LANCZOS_COEFF[i] / (z + i)
  t: float = z + _LANCZOS_G + 0.5
  tz: float = t ** (z + 0.5)
  return math.sqrt(2.0 * math.pi) * tz * math.exp(-t) * x


def BetaIncompleteCF(a: float, b: float, x: float, /) -> float:
  """Compute continued fraction for the regularized incomplete beta function.

  Uses the modified Lentz algorithm to evaluate the continued fraction
  expansion of I_x(a, b) efficiently and stably.

  Args:
    a (float): First shape parameter (> 0).
    b (float): Second shape parameter (> 0).
    x (float): Point at which to evaluate (0 ≤ x ≤ 1).

  Returns:
    float: The continued fraction value.

  Notes:
    - Internal helper for `_BetaIncomplete`.
    - Convergence is typically achieved in < 100 iterations for typical inputs.
    - Uses a floor of 1e-30 to prevent division by zero.

  """
  qab: float = a + b
  qap: float = a + 1.0
  qam: float = a - 1.0
  c: float = 1.0
  d: float = 1.0 / _NSG(1.0 - qab * x / qap)
  h: float = d
  aa: float
  delta: float
  m2: int
  for m in range(1, _BETA_INCOMPLETE_MAX_ITER + 1):
    m2 = 2 * m
    # even step
    aa = m * (b - m) * x / ((qam + m2) * (a + m2))
    c, d = _NSG(1.0 + aa / c), 1.0 / _NSG(1.0 + aa * d)
    h *= d * c
    # odd step
    aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
    c, d = _NSG(1.0 + aa / c), 1.0 / _NSG(1.0 + aa * d)
    delta = d * c
    h *= delta
    if abs(delta - 1.0) < _BETA_INCOMPLETE_TOL:
      break
  return h


def BetaIncomplete(a: float, b: float, x: float, /) -> float:
  """Compute the regularized incomplete beta function I_x(a, b).

  The regularized incomplete beta function is defined as:
    I_x(a, b) = B(x; a, b) / B(a, b)
  where B(x; a, b) is the incomplete beta function and B(a, b) is the
  complete beta function.

  Args:
    a (float): First shape parameter (> 0).
    b (float): Second shape parameter (> 0).
    x (float): Upper limit of integration (0 ≤ x ≤ 1).

  Returns:
    float: I_x(a, b), the regularized incomplete beta at x.

  Raises:
    base.InputError: If x is outside [0, 1].

  Notes:
    - Uses continued fraction expansion with Lentz algorithm.
    - For numerical stability, uses the symmetry relation when
      x > (a + 1) / (a + b + 2).

  """
  if x < 0.0 or x > 1.0:
    raise base.InputError(f'x must be in [0, 1], got {x}')
  if x == 0.0:
    return 0.0
  if x == 1.0:
    return 1.0
  log_beta: float = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
  front: float = math.exp(math.log(x) * a + math.log(1.0 - x) * b - log_beta) / a
  if x < (a + 1.0) / (a + b + 2.0):
    return front * BetaIncompleteCF(a, b, x)
  return 1.0 - front * BetaIncompleteCF(b, a, 1.0 - x) * a / b


def StudentTCDF(t_val: float, df: float, /) -> float:
  """Compute the cumulative distribution function (CDF) of Student's t-distribution.

  The CDF gives the probability P(T ≤ t) where T follows a t-distribution
  with `df` degrees of freedom.

  Args:
    t_val (float): The t-statistic value.
    df (float): Degrees of freedom (> 0).

  Returns:
    float: Probability P(T ≤ t_val), in range [0, 1].

  Notes:
    - Uses the relationship between the t-distribution CDF and the
      regularized incomplete beta function.
    - For t ≥ 0: CDF = 0.5 + 0.5 * (1 - I_x(df/2, 0.5))
    - For t < 0: CDF = 0.5 * I_x(df/2, 0.5)
    - where x = df / (df + t²)

  """
  x: float = df / (df + t_val * t_val)
  prob: float = 0.5 * BetaIncomplete(df / 2.0, 0.5, x)
  return 0.5 + (0.5 - prob) if t_val >= 0 else prob


def StudentTPPF(q: float, df: float, /) -> float:
  """Compute the percent point function (inverse CDF) of Student's t-distribution.

  Given a probability q, find the value t such that P(T ≤ t) = q,
  where T follows a t-distribution with `df` degrees of freedom.

  Args:
    q (float): Probability (0 < q < 1).
    df (float): Degrees of freedom (> 0).

  Returns:
    float: The t-value such that CDF(t) = q.

  Raises:
    base.InputError: If q is not in (0, 1).

  Notes:
    - Uses Newton-Raphson iteration with an initial guess from
      the normal distribution approximation.
    - Converges to ~12 decimal places in typical cases.

  """
  if not 0.0 < q < 1.0:
    raise base.InputError(f'q must be in (0, 1), got {q}')
  # Special case: q=0.5 is exactly 0 by symmetry
  if q == 0.5:  # noqa: PLR2004
    return 0.0
  # Initial guess using inverse normal approximation (Abramowitz & Stegun 26.2.23)
  if q < 0.5:  # noqa: PLR2004
    sign: float = -1.0
    p: float = q
  else:
    sign = 1.0
    p = 1.0 - q
  # Protect against log(0) when p is very close to 0
  p = max(p, 1e-300)
  t_approx: float = math.sqrt(-2.0 * math.log(p))
  c0 = 2.515517
  c1 = 0.802853
  c2 = 0.010328
  d1 = 1.432788
  d2 = 0.189269
  d3 = 0.001308
  x0: float = sign * (
    t_approx
    - (c0 + c1 * t_approx + c2 * t_approx**2)
    / (1 + d1 * t_approx + d2 * t_approx**2 + d3 * t_approx**3)
  )
  # Newton-Raphson refinement
  for _ in range(50):
    cdf_val: float = StudentTCDF(x0, df)
    # PDF of Student's t-distribution (computed in log-space to avoid overflow for large df)
    log_pdf: float = (
      math.lgamma((df + 1) / 2)
      - 0.5 * math.log(df * math.pi)
      - math.lgamma(df / 2)
      - ((df + 1) / 2) * math.log(1 + x0**2 / df)
    )
    pdf_val: float = _NSG(math.exp(log_pdf))
    x1: float = x0 - (cdf_val - q) / pdf_val
    if abs(x1 - x0) < _STUDENT_SMALL:
      return x1
    x0 = x1
  return x0  # pragma: no cover - Newton-Raphson always converges for t-distribution


def SampleVariance(data: list[int | float], mean: float, /) -> float:
  """Compute sample variance with Bessel's correction (n-1 denominator).

  Args:
    data (list[int | float]): Sequence of numeric measurements, with len(data) >= 2.
    mean (float): Pre-computed mean of the data.

  Returns:
    float: Sample variance s² = Σ(xᵢ - x̄)² / (n - 1).

  Raises:
    base.InputError: If len(data) < 2.

  """
  if (data_sz := len(data)) < 2:  # noqa: PLR2004
    raise base.InputError(f'sample variance requires at least 2 data points, got {data_sz}')
  return sum((x - mean) ** 2 for x in data) / float(data_sz - 1)


def StandardErrorOfMean(data: list[int | float], /) -> tuple[float, float]:
  """Compute the mean and standard error of the mean (SEM).

  The SEM is the standard deviation of the sampling distribution of the
  sample mean, computed as s / √n where s is the sample standard deviation.

  Args:
    data (list[int | float]): Sequence of numeric measurements (n >= 2).

  Returns:
    tuple[float, float]: (mean, SEM) where:
      - mean: arithmetic mean of the data
      - SEM: standard error of the mean (σ / √n)

  Notes:
    - Assumes len(data) >= 2; returns (mean, inf) for single element handled by caller.
    - Uses sample standard deviation (Bessel's correction).

  """  # noqa: RUF002
  n: int = len(data)
  mean: float = sum(data) / n
  variance: float = SampleVariance(data, mean)
  return (mean, math.sqrt(variance / n))


def StudentTInterval(
  confidence: float, df: int, loc: float, scale: float, /
) -> tuple[float, float]:
  """Compute a symmetric confidence interval using Student's t-distribution.

  Args:
    confidence (float): Confidence level (e.g., 0.95 for 95% CI).
    df (int): Degrees of freedom (n - 1 for a sample of size n).
    loc (float): Center of the interval (typically the sample mean).
    scale (float): Scale parameter (typically the SEM).

  Returns:
    tuple[float, float]: (lower_bound, upper_bound) of the confidence interval.

  Notes:
    - The interval is symmetric around `loc`:
        [loc - t_crit * scale, loc + t_crit * scale]
    - where t_crit is the critical t-value for the given confidence and df.

  """
  alpha: float = 1.0 - confidence
  t_crit: float = StudentTPPF(1.0 - alpha / 2.0, df)
  margin: float = t_crit * scale
  return (loc - margin, loc + margin)


def MeasurementStats(
  data: list[int | float], /, *, confidence: float = 0.95
) -> tuple[int, float, float, float, tuple[float, float], float]:
  """Compute descriptive statistics for repeated measurements.

  Given N ≥ 1 measurements, this function computes the sample mean, the
  standard error of the mean (SEM), and the symmetric error estimate for
  the chosen confidence interval using Student's t distribution.

  Notes:
    • If only one measurement is given, SEM and error are reported as +∞ and
      the confidence interval is (-∞, +∞).
    • This function assumes the underlying distribution is approximately
      normal, or n is large enough for the Central Limit Theorem to apply.

  Args:
    data (list[int | float]): Sequence of numeric measurements.
    confidence (float, optional): Confidence level for the interval, 0.5 <= confidence < 1;
        defaults to 0.95 (95% confidence interval).

  Returns:
    tuple:
      - n (int): number of measurements.
      - mean (float): arithmetic mean of the data
      - sem (float): standard error of the mean, sigma / √n
      - error (float): half-width of the confidence interval (mean ± error)
      - ci (tuple[float, float]): lower and upper confidence interval bounds
      - confidence (float): the confidence level used

  Raises:
    base.InputError: if the input list is empty.

  """
  # test inputs
  n: int = len(data)
  if not n:
    raise base.InputError('no data')
  if not 0.5 <= confidence < 1.0:  # noqa: PLR2004
    raise base.InputError(f'invalid confidence: {confidence=}')
  # solve trivial case
  if n == 1:
    return (n, float(data[0]), math.inf, math.inf, (-math.inf, math.inf), confidence)
  # compute statistics using local implementation (no scipy/numpy dependency)
  mean: float
  sem: float
  mean, sem = StandardErrorOfMean(data)
  ci: tuple[float, float] = StudentTInterval(confidence, n - 1, mean, sem)
  t_crit: float = StudentTPPF((1.0 + confidence) / 2.0, n - 1)
  error: float = t_crit * sem  # half-width of the CI
  return (n, mean, sem, error, ci, confidence)
