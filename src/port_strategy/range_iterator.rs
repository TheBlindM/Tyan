use gcd::Gcd;
use rand::Rng;
use std::convert::TryInto;

pub struct RangeIterator {
    active: bool,
    normalized_end: u32,
    normalized_first_pick: u32,
    normalized_pick: u32,
    actual_start: u32,
    step: u32,
}

/// 遵循 `线性同余生成器 (Linear Congruential Generator)` 算法的迭代器。
///
/// 更多信息请参阅：<https://en.wikipedia.org/wiki/Linear_congruential_generator>
impl RangeIterator {
    /// 接收范围的起始和结束值，并在选择一个互质数作为算法的步长之前
    /// 对这些值进行标准化。
    ///
    /// 例如，范围 `1000-2500` 在进入算法之前将被标准化为 `0-1500`。
    pub fn new(start: u32, end: u32) -> Self {
        let normalized_end = end - start + 1;
        let step = pick_random_coprime(normalized_end);

        // 随机选择范围内的的一个数字作为第一个选择
        // 并将其赋值给 pick。
        let mut rng = rand::rng();
        let normalized_first_pick = rng.random_range(0..normalized_end);

        Self {
            active: true,
            normalized_end,
            step,
            normalized_first_pick,
            normalized_pick: normalized_first_pick,
            actual_start: start,
        }
    }
}

impl Iterator for RangeIterator {
    type Item = u16;

    // 下一步总是受公式约束：N+1 = (N + STEP) % TOP_OF_THE_RANGE
    // 只有当我们生成的数字等于第一个生成的数字时，它才会停止。
    fn next(&mut self) -> Option<Self::Item> {
        if !self.active {
            return None;
        }

        let current_pick = self.normalized_pick;
        let next_pick = (current_pick + self.step) % self.normalized_end;

        // 如果下一个选择等于第一个选择，这意味着
        // 我们已经遍历了整个范围。
        if next_pick == self.normalized_first_pick {
            self.active = false;
        }

        self.normalized_pick = next_pick;
        Some(
            (self.actual_start + current_pick)
                .try_into()
                .expect("Could not convert u32 to u16"),
        )
    }
}

fn pick_random_coprime(end: u32) -> u32 {
    let range_boundary = end / 4;
    let lower_range = range_boundary;
    let upper_range = end - range_boundary;
    let mut rng = rand::rng();
    let mut candidate = rng.random_range(lower_range..upper_range);

    for _ in 0..10 {
        if end.gcd(candidate) == 1 {
            return candidate;
        }
        candidate = rng.random_range(lower_range..upper_range);
    }

    end - 1
}

#[cfg(test)]
mod tests {
    use super::RangeIterator;

    #[test]
    fn range_iterator_iterates_through_the_entire_range() {
        let result = generate_sorted_range(1, 10);
        let expected_range = (1..=10).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = generate_sorted_range(1, 100);
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = generate_sorted_range(1, 1000);
        let expected_range = (1..=1000).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = generate_sorted_range(1, 65_535);
        let expected_range = (1..=65_535).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);

        let result = generate_sorted_range(1000, 2000);
        let expected_range = (1000..=2000).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }

    fn generate_sorted_range(start: u32, end: u32) -> Vec<u16> {
        let range = RangeIterator::new(start, end);
        let mut result = range.into_iter().collect::<Vec<u16>>();
        result.sort_unstable();

        result
    }
}
