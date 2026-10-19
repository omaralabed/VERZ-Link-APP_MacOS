//! Small deterministic generator: the same seed always replays the same run.

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1_u64 << 53) as f64
    }

    pub fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && self.unit() < p
    }

    /// Exponential with the given mean.
    pub fn exp(&mut self, mean: f64) -> f64 {
        if mean <= 0.0 {
            0.0
        } else {
            -mean * (1.0 - self.unit()).ln()
        }
    }

    /// Standard normal (Box-Muller).
    pub fn normal(&mut self) -> f64 {
        let u = self.unit().max(1e-12);
        let v = self.unit();
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}
