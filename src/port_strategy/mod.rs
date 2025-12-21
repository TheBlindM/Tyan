//! 提供了一种保存端口扫描配置选项的方法。
mod range_iterator;
use crate::input::{ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;

/// 表示端口扫描的选项。
///
/// 目前所有这些选项都涉及范围，但在将来
/// 它也将包含自定义端口列表。
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    /// 根据给定的范围、端口列表和扫描顺序选择端口策略。
    pub fn pick(ports: Vec<u16>, order: ScanOrder) -> Self {
        match order {
            // 如果是顺序扫描且有指定端口列表，则使用 Manual 策略
            ScanOrder::Serial => PortStrategy::Manual(ports),
            // 如果是随机扫描且有指定端口列表，则打乱端口列表顺序后使用 Manual 策略
            ScanOrder::Random => {
                let mut rng = rng();
                let mut ports = ports;
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
        }
    }

    /// 生成扫描顺序的端口列表。
    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(range) => range.generate(),
            PortStrategy::Random(range) => range.generate(),
        }
    }
}

/// 与端口策略关联的 Trait。每个 PortStrategy 必须能够
/// 为未来的端口扫描生成一个顺序。
trait RangeOrder {
    fn generate(&self) -> Vec<u16>;
}

/// 顾名思义，SerialRange 将始终按升序生成一个向量。
#[derive(Debug)]
pub struct SerialRange {
    start: u16,
    end: u16,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

/// 顾名思义，RandomRange 将始终生成一个具有随机顺序的向量。
/// 该向量是按照 LCG 算法构建的。
#[derive(Debug)]
pub struct RandomRange {
    start: u16,
    end: u16,
}

impl RangeOrder for RandomRange {
    // 目前使用 RangeIterator 生成范围 + 打乱向量
    // 几乎是一样的。它的优势在于一旦我们
    // 必须为不同的 IP 生成不同的范围而不存储
    // 实际的向量。
    //
    // RangeIterator 的另一个好处是它总是生成一个
    // 数组中项目之间具有一定距离的范围。由于算法的工作方式，
    // 端口号彼此接近的几率非常小。
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new(self.start.into(), self.end.into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{ScanOrder};

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(vec![80, 443], ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick((1..10).collect(), ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }
}
