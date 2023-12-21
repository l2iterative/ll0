use std::fmt::{Display, Formatter};
use std::ops::{Add, BitAnd, BitXor, Mul, Shl, Sub};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Fp(pub u32);

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Fp4(pub Fp, pub Fp, pub Fp, pub Fp);

impl Fp {
    pub const ZERO: Fp = Self(0u32);
}

impl Add<Fp> for &Fp {
    type Output = Fp;

    fn add(self, rhs: Fp) -> Self::Output {
        Fp(((self.0 as u64 + rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Add<Fp> for Fp {
    type Output = Fp;

    fn add(self, rhs: Fp) -> Self::Output {
        Fp(((self.0 as u64 + rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Add for &Fp {
    type Output = Fp;

    fn add(self, rhs: &Fp) -> Self::Output {
        Fp(((self.0 as u64 + rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Sub for &Fp {
    type Output = Fp;

    fn sub(self, rhs: Self) -> Self::Output {
        Fp(((2013265921u64 + self.0 as u64 - rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Mul for &Fp {
    type Output = Fp;

    fn mul(self, rhs: Self) -> Self::Output {
        Fp(((self.0 as u64 * rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Mul<Fp> for &Fp {
    type Output = Fp;

    fn mul(self, rhs: Fp) -> Self::Output {
        Fp(((self.0 as u64 * rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Mul<Fp> for Fp {
    type Output = Fp;

    fn mul(self, rhs: Self) -> Self::Output {
        Fp(((self.0 as u64 * rhs.0 as u64) % 2013265921u64) as u32)
    }
}

impl Shl<usize> for Fp {
    type Output = Fp;

    fn shl(self, rhs: usize) -> Self::Output {
        Fp(self.0 << rhs)
    }
}

impl BitAnd for &Fp {
    type Output = Fp;

    fn bitand(self, rhs: Self) -> Self::Output {
        Fp(self.0 & rhs.0)
    }
}

impl BitXor for &Fp {
    type Output = Fp;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Fp(self.0 ^ rhs.0)
    }
}

impl Display for Fp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Add for &Fp4 {
    type Output = Fp4;

    fn add(self, rhs: Self) -> Fp4 {
        Fp4(
            &self.0 + &rhs.0,
            &self.1 + &rhs.1,
            &self.2 + &rhs.2,
            &self.3 + &rhs.2,
        )
    }
}

impl Sub for &Fp4 {
    type Output = Fp4;

    fn sub(self, rhs: Self) -> Self::Output {
        Fp4(
            &self.0 - &rhs.0,
            &self.1 - &rhs.1,
            &self.2 - &rhs.2,
            &self.3 - &rhs.2,
        )
    }
}

impl Mul for &Fp4 {
    type Output = Fp4;

    fn mul(self, rhs: Self) -> Self::Output {
        const NBETA: Fp = Fp(2013265910);

        Fp4(
            &self.0 * &rhs.0 + NBETA * (&self.1 * &rhs.3 + &self.2 * &rhs.2 + &self.3 * &rhs.1),
            &self.0 * &rhs.1 + &self.1 * &rhs.0 + NBETA * (&self.2 * &rhs.3 + &self.3 * &rhs.2),
            &self.0 * &rhs.2 + &self.1 * &rhs.1 + &self.2 * &rhs.0 + NBETA * (&self.3 * &rhs.3),
            &self.0 * &rhs.3 + &self.1 * &rhs.2 + &self.2 * &rhs.1 + &self.3 * &rhs.0,
        )
    }
}

impl Display for Fp4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.1 == Fp::ZERO && self.2 == Fp::ZERO && self.3 == Fp::ZERO {
            f.write_fmt(format_args!("{}", self.0))
        } else if self.2 == Fp::ZERO && self.3 == Fp::ZERO {
            f.write_fmt(format_args!("({}, {})", self.0, self.1))
        } else {
            f.write_fmt(format_args!(
                "({}, {}, {}, {})",
                self.0, self.1, self.2, self.3
            ))
        }
    }
}

impl Fp4 {
    pub fn new(v1: Fp, v2: Fp, v3: Fp, v4: Fp) -> Self {
        Self(v1, v2, v3, v4)
    }

    pub fn inv(&self) -> Self {
        self.pow(2013265919usize)
    }

    fn pow(&self, n: usize) -> Self {
        let mut n = n;
        let mut tot = Self(Fp(1), Fp::ZERO, Fp::ZERO, Fp::ZERO);
        let mut x = self.clone();
        while n != 0 {
            if n % 2 == 1 {
                tot = &tot * &x;
            }
            n /= 2;
            x = &x * &x;
        }
        tot
    }
}
