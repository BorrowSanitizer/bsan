use core::fmt::Display;

/// Indicates which kind of access is being performed.
#[derive(Copy, Clone, Hash, PartialEq, Eq, Debug)]
pub enum AccessKind {
    Read,
    Write,
}

#[allow(clippy::recursive_format_impl)]
impl Display for AccessKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AccessKind<{self}>")
    }
}

/// Relative position of the access
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessRelatedness {
    /// The accessed pointer is the current one
    This,
    /// The accessed pointer is a (transitive) child of the current one.
    // Current pointer is excluded (unlike in some other places of this module
    // where "child" is inclusive).
    StrictChildAccess,
    /// The accessed pointer is a (transitive) parent of the current one.
    // Current pointer is excluded.
    AncestorAccess,
    /// The accessed pointer is neither of the above.
    // It's a cousin/uncle/etc., something in a side branch.
    CousinAccess,
}

impl AccessRelatedness {
    /// Check that access is either Ancestor or Distant, i.e. not
    /// a transitive child (initial pointer included).
    pub fn is_foreign(self) -> bool {
        matches!(self, AccessRelatedness::AncestorAccess | AccessRelatedness::CousinAccess)
    }
}

#[macro_export]
macro_rules! vec_in {
    ($alloc:expr) => {
        Vec::new_in(alloc)
    };

    // Handle the custom "Elem" syntax for range initialization
    // This is more specific, so it must come before the next arm.
    ($alloc:expr, Elem { range: $range:expr, init: $init:expr }) => (
        {
            let init_fn = $init;
            let range = $range;

            // Be efficient: pre-allocate if the iterator gives a size hint
            let (lower, upper) = range.size_hint();
            let capacity = upper.unwrap_or(lower);
            let mut vec = Vec::with_capacity_in(capacity, $alloc);

            // Create the items by iterating and calling the initializer
            for i in range {
                vec.push(init_fn(i));
            }
            vec
        }
    );

    // Handle a comma-separated list of expressions (your original arm)
    // This is a general "catch-all", so it must come last.
    ($alloc:expr, $($x:expr),+ $(,)?) => (
        {
            // This is a simple way, but not the most efficient for many elements.
            // A more advanced macro could count the elements to pre-allocate.
            let mut vec = Vec::new_in($alloc);
            $(
                vec.push($x);
            )+
            vec
        }
    );
}
