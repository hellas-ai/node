use std::collections::{VecDeque, vec_deque};

#[derive(Debug, Default)]
pub(crate) struct Effects<E> {
    queue: VecDeque<E>,
}

impl<E> Effects<E> {
    pub(crate) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub(crate) fn push(&mut self, effect: E) {
        self.queue.push_back(effect);
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> vec_deque::Iter<'_, E> {
        self.queue.iter()
    }
}

impl<E> IntoIterator for Effects<E> {
    type Item = E;
    type IntoIter = vec_deque::IntoIter<E>;

    fn into_iter(self) -> Self::IntoIter {
        self.queue.into_iter()
    }
}
