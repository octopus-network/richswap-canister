use candid::{
    types::{Serializer, Type, TypeInner},
    CandidType,
};
use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign,
};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Decimal {
    inner: rust_decimal::Decimal,
}

impl CandidType for Decimal {
    fn _ty() -> Type {
        TypeInner::Text.into()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_text(&self.inner.to_string())
    }
}

impl Default for Decimal {
    fn default() -> Self {
        Self::zero()
    }
}

impl Decimal {
    pub const fn zero() -> Decimal {
        Self {
            inner: rust_decimal::Decimal::ZERO,
        }
    }

    pub const fn one() -> Decimal {
        Self {
            inner: rust_decimal::Decimal::ONE,
        }
    }

    pub fn new(num: i64, scale: u32) -> Decimal {
        Self {
            inner: rust_decimal::Decimal::new(num, scale),
        }
    }

    pub fn sqrt(&self) -> Option<Decimal> {
        use rust_decimal::MathematicalOps;
        Some(Decimal {
            inner: self.inner.sqrt()?,
        })
    }

    pub fn try_from_primitive(num: i128, scale: u32) -> Option<Decimal> {
        Some(Self {
            inner: rust_decimal::Decimal::try_from_i128_with_scale(num, scale).ok()?,
        })
    }

    pub fn scale(&self) -> u32 {
        self.inner.scale()
    }

    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    pub fn is_sign_negative(&self) -> bool {
        self.inner.is_sign_negative()
    }

    pub fn is_sign_positive(&self) -> bool {
        self.inner.is_sign_positive()
    }

    pub fn mantissa(&self) -> i128 {
        self.inner.mantissa()
    }

    pub fn set_scale(&mut self, scale: u8) -> Option<()> {
        self.inner.set_scale(scale as u32).ok()
    }

    pub fn truncate(&self, scale: u8) -> Decimal {
        Decimal {
            inner: self.inner.trunc_with_scale(scale as u32),
        }
    }

    pub fn checked_mul(self, other: Decimal) -> Option<Decimal> {
        Some(Decimal {
            inner: self.inner.checked_mul(other.inner)?,
        })
    }

    pub fn checked_add(self, other: Decimal) -> Option<Decimal> {
        Some(Decimal {
            inner: self.inner.checked_add(other.inner)?,
        })
    }

    pub fn checked_sub(self, other: Decimal) -> Option<Decimal> {
        Some(Decimal {
            inner: self.inner.checked_sub(other.inner)?,
        })
    }

    pub fn checked_div(self, other: Decimal) -> Option<Decimal> {
        Some(Decimal {
            inner: self.inner.checked_div(other.inner)?,
        })
    }
}

impl Add for Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn add(self, other: Decimal) -> Decimal {
        Decimal {
            inner: self.inner + other.inner,
        }
    }
}

impl<'a, 'b> Add<&'b Decimal> for &'a Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn add(self, other: &Decimal) -> Decimal {
        Decimal {
            inner: self.inner + other.inner,
        }
    }
}

impl Div for Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn div(self, other: Decimal) -> Decimal {
        Decimal {
            inner: self.inner / other.inner,
        }
    }
}

impl<'a, 'b> Div<&'b Decimal> for &'a Decimal {
    type Output = Decimal;

    #[inline]
    fn div(self, other: &Decimal) -> Decimal {
        Decimal {
            inner: self.inner / other.inner,
        }
    }
}

impl Mul for Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn mul(self, other: Decimal) -> Decimal {
        Decimal {
            inner: self.inner * other.inner,
        }
    }
}

impl<'a, 'b> Mul<&'b Decimal> for &'a Decimal {
    type Output = Decimal;

    #[inline]
    fn mul(self, other: &Decimal) -> Decimal {
        Decimal {
            inner: self.inner * other.inner,
        }
    }
}

impl Rem for Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn rem(self, other: Decimal) -> Decimal {
        Decimal {
            inner: self.inner % other.inner,
        }
    }
}

impl<'a, 'b> Rem<&'b Decimal> for &'a Decimal {
    type Output = Decimal;

    #[inline]
    fn rem(self, other: &Decimal) -> Decimal {
        Decimal {
            inner: self.inner % other.inner,
        }
    }
}

impl Sub for Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn sub(self, other: Decimal) -> Decimal {
        Decimal {
            inner: self.inner - other.inner,
        }
    }
}

impl<'a, 'b> Sub<&'b Decimal> for &'a Decimal {
    type Output = Decimal;

    #[inline(always)]
    fn sub(self, other: &Decimal) -> Decimal {
        Decimal {
            inner: self.inner - other.inner,
        }
    }
}

impl AddAssign for Decimal {
    fn add_assign(&mut self, other: Decimal) {
        self.inner += other.inner;
    }
}

impl<'a> AddAssign<&'a Decimal> for Decimal {
    fn add_assign(&mut self, other: &'a Decimal) {
        Decimal::add_assign(self, *other)
    }
}

impl<'a> AddAssign<Decimal> for &'a mut Decimal {
    fn add_assign(&mut self, other: Decimal) {
        Decimal::add_assign(*self, other)
    }
}

impl<'a> AddAssign<&'a Decimal> for &'a mut Decimal {
    fn add_assign(&mut self, other: &'a Decimal) {
        Decimal::add_assign(*self, *other)
    }
}

impl SubAssign for Decimal {
    fn sub_assign(&mut self, other: Decimal) {
        self.inner -= other.inner;
    }
}

impl<'a> SubAssign<&'a Decimal> for Decimal {
    fn sub_assign(&mut self, other: &'a Decimal) {
        Decimal::sub_assign(self, *other)
    }
}

impl<'a> SubAssign<Decimal> for &'a mut Decimal {
    fn sub_assign(&mut self, other: Decimal) {
        Decimal::sub_assign(*self, other)
    }
}

impl<'a> SubAssign<&'a Decimal> for &'a mut Decimal {
    fn sub_assign(&mut self, other: &'a Decimal) {
        Decimal::sub_assign(*self, *other)
    }
}

impl MulAssign for Decimal {
    fn mul_assign(&mut self, other: Decimal) {
        self.inner *= other.inner;
    }
}

impl<'a> MulAssign<&'a Decimal> for Decimal {
    fn mul_assign(&mut self, other: &'a Decimal) {
        Decimal::mul_assign(self, *other)
    }
}

impl<'a> MulAssign<Decimal> for &'a mut Decimal {
    fn mul_assign(&mut self, other: Decimal) {
        Decimal::mul_assign(*self, other)
    }
}

impl<'a> MulAssign<&'a Decimal> for &'a mut Decimal {
    fn mul_assign(&mut self, other: &'a Decimal) {
        Decimal::mul_assign(*self, *other)
    }
}

impl DivAssign for Decimal {
    fn div_assign(&mut self, other: Decimal) {
        self.inner /= other.inner;
    }
}

impl<'a> DivAssign<&'a Decimal> for Decimal {
    fn div_assign(&mut self, other: &'a Decimal) {
        Decimal::div_assign(self, *other)
    }
}

impl<'a> DivAssign<Decimal> for &'a mut Decimal {
    fn div_assign(&mut self, other: Decimal) {
        Decimal::div_assign(*self, other)
    }
}

impl<'a> DivAssign<&'a Decimal> for &'a mut Decimal {
    fn div_assign(&mut self, other: &'a Decimal) {
        Decimal::div_assign(*self, *other)
    }
}

impl RemAssign for Decimal {
    fn rem_assign(&mut self, other: Decimal) {
        self.inner %= other.inner;
    }
}

impl<'a> RemAssign<&'a Decimal> for Decimal {
    fn rem_assign(&mut self, other: &'a Decimal) {
        Decimal::rem_assign(self, *other)
    }
}

impl<'a> RemAssign<Decimal> for &'a mut Decimal {
    fn rem_assign(&mut self, other: Decimal) {
        Decimal::rem_assign(*self, other)
    }
}

impl<'a> RemAssign<&'a Decimal> for &'a mut Decimal {
    fn rem_assign(&mut self, other: &'a Decimal) {
        Decimal::rem_assign(*self, *other)
    }
}

impl Neg for Decimal {
    type Output = Decimal;

    fn neg(self) -> Decimal {
        Self { inner: -self.inner }
    }
}

impl<'a> Neg for &'a Decimal {
    type Output = Decimal;

    fn neg(self) -> Decimal {
        Decimal {
            inner: -self.inner.clone(),
        }
    }
}

impl std::str::FromStr for Decimal {
    type Err = rust_decimal::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            inner: rust_decimal::Decimal::from_str(s)?,
        })
    }
}

struct DecimalVisitor;

impl<'de> serde::de::Visitor<'de> for DecimalVisitor {
    type Value = Decimal;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "a Decimal type representing a fixed-point number"
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Decimal, E>
    where
        E: serde::de::Error,
    {
        use std::str::FromStr;
        let inner = rust_decimal::Decimal::from_str(value)
            .or_else(|_| rust_decimal::Decimal::from_scientific(value))
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(value), &self))?;
        Ok(Decimal { inner })
    }
}

impl<'de> serde::Deserialize<'de> for Decimal {
    fn deserialize<D>(deserializer: D) -> Result<Decimal, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(DecimalVisitor)
    }
}

impl serde::Serialize for Decimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}
