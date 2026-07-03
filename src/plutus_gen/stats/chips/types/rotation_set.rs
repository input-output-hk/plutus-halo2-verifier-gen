/// A rotation applied to an advice column query in a gate or lookup.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RotationSet {
    pub(super) first: bool,
    pub(super) prev: bool,
    pub(super) curr: bool,
    pub(super) next: bool,
    pub(super) next2: bool,
    pub(super) next3: bool,
    pub(super) last: bool,
}

impl RotationSet {
    pub(crate) fn new(
        first: bool,
        prev: bool,
        curr: bool,
        next: bool,
        next2: bool,
        next3: bool,
        last: bool,
    ) -> Self {
        Self {
            first,
            prev,
            curr,
            next,
            next2,
            next3,
            last,
        }
    }

    pub(crate) fn curr() -> Self {
        Self {
            curr: true,
            ..Self::default()
        }
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        self.first |= other.first;
        self.prev |= other.prev;
        self.curr |= other.curr;
        self.next |= other.next;
        self.next2 |= other.next2;
        self.next3 |= other.next3;
        self.last |= other.last;
    }

    pub(crate) fn count(&self) -> usize {
        [
            self.first, self.prev, self.curr, self.next, self.next2, self.next3, self.last,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.first
            && !self.prev
            && !self.curr
            && !self.next
            && !self.next2
            && !self.next3
            && !self.last
    }
}
