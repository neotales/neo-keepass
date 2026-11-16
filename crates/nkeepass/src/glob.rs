//! The `secrets ls` path glob.
//!
//! A group path is one string -- `Root/Work/mail1` -- and the pattern is
//! matched against all of it, so `*` has always been able to cross a `/` and
//! mean "any depth". That is the whole of the original syntax, and it is the
//! constraint this module is built around: a pattern written with `*` and `?`
//! alone must keep meaning what it meant, because a script already depends on
//! it. Everything added beyond that -- `{a,b}`, `[a-z]`, `**/` -- sits beside
//! the old rules rather than on top of them, and
//! `pinned_glob_semantics_are_preserved` below is the contract that says so.
//!
//! ## Why not `globset`
//!
//! `globset` is ripgrep's engine and it is the obvious candidate. It was
//! evaluated at 0.4.20 and rejected, because three of its rules are not
//! configurable and each one silently retargets a pattern that works today.
//!
//! - A backslash is an escape, so `a\b` matches `ab` and not `a\b`. Adding an
//!   escape to a syntax that has never had one retargets every existing
//!   pattern that happens to contain one, and there is no setting to decline.
//! - An unclosed `[` is a hard *error* -- "unclosed character class" -- rather
//!   than a literal `[`, and a `}` with no `{` is an error too. Both are
//!   literals today, so preserving them means deciding well-formedness before
//!   handing the pattern over, which is a parser rather than a setting.
//! - `{db}` is the class `[db]`, not the three bytes `{db}`. There is no
//!   switch for "a brace group with no comma is literal".
//!
//! Its `literal_separator(false)` does buy back the one thing the old `*`
//! needs, and it does have the property that matters most for an
//! attacker-influenced pattern: it never backtracks, because it compiles to
//! an automaton. So this module does the same thing, in a couple of hundred
//! lines, and keeps six crates out of a binary whose whole point is a small
//! attack surface.
//!
//! One thing `globset` got right is worth keeping: its `?` and its classes
//! are byte-oriented rather than character-oriented (`[é]` does not match
//! `é`), which is what made the byte semantics below cheap to preserve rather
//! than a wart to work around.
//!
//! ## Cost
//!
//! The pattern is compiled once, before the walk, and matching simulates a
//! Thompson NFA: a set of live instructions carried forward one byte at a
//! time. Never a recursive descent, never a retry.
//!
//! - Compile is O(pattern bytes) and alternation is *not* expanded. Expanding
//!   `{a,b}` into two patterns is the exponential mistake -- a hundred
//!   two-way groups is 2^100 patterns -- and it is why the program is an
//!   automaton with a loop rather than a tree of alternatives.
//! - A match is O(pattern states x path bytes) worst case, in O(pattern
//!   states) of scratch. No shape of pattern changes that, so a hostile
//!   pattern cannot buy more than a constant factor, and the length cap in
//!   `compile_glob` bounds the constant.
//! - Brace nesting is capped at `MAX_BRACE_DEPTH` rather than being left to
//!   the pattern-length cap, because the *compiler* is the recursive part and
//!   it should not depend on a limit declared in another file.
//!
//! So there is no pattern that takes exponential time, and no pattern that
//! overflows the stack while matching.

/// How deep `{` may nest before the inner one is taken as a literal byte.
const MAX_BRACE_DEPTH: usize = 64;

/// A jump target that has not been filled in yet.
///
/// Not `0`: `0` is a real instruction index, and a sentinel that is also a
/// legal value cannot be told apart from one that has been patched.
const UNSET: usize = usize::MAX;

/// One instruction of the compiled pattern.
#[derive(Clone, Copy)]
enum Inst {
    /// Consume one exact byte. Every other byte in a title takes this path,
    /// including `/` and every byte of a multi-byte character.
    Byte(u8),
    /// Consume any one byte: `?`.
    Any,
    /// Consume any byte except `/`: the body of one `**/` component.
    AnyNotSlash,
    /// Consume one byte from a set, or from its complement when negated.
    Class { bits: [u64; 4], negated: bool },
    /// Consume nothing and continue at either target. A `*` and a branch of a
    /// `{a,b}` are both one of these, which is what lets a loop and a choice
    /// be the same instruction.
    Split(usize, usize),
    /// Consume nothing and continue at one target.
    Jump(usize),
    /// Consume nothing and accept. Always the last instruction.
    Accept,
}

impl Inst {
    /// Whether this instruction is the one that consumes `byte`.
    fn consumes(self, byte: u8) -> bool {
        match self {
            Self::Byte(want) => want == byte,
            Self::Any => true,
            Self::AnyNotSlash => byte != b'/',
            Self::Class { bits, negated } => in_set(bits, byte) != negated,
            Self::Split(..) | Self::Jump(_) | Self::Accept => false,
        }
    }

    /// The zero-width targets, if any. A byte-consuming instruction has none,
    /// which is what keeps the simulation from ever needing to look ahead.
    fn edges(self) -> Option<(usize, usize)> {
        match self {
            Self::Split(first, second) => Some((first, second)),
            Self::Jump(target) => Some((target, target)),
            Self::Byte(_) | Self::Any | Self::AnyNotSlash | Self::Class { .. } | Self::Accept => {
                None
            }
        }
    }
}

/// Whether a class's set holds `byte`.
fn in_set(bits: [u64; 4], byte: u8) -> bool {
    bits[usize::from(byte >> 6)] & (1 << (byte & 63)) != 0
}

/// Adds `byte` to a class's set.
fn add_to_set(bits: &mut [u64; 4], byte: u8) {
    bits[usize::from(byte >> 6)] |= 1 << (byte & 63);
}

/// A pattern compiled once and matched against every path in the tree.
pub struct Glob {
    program: Vec<Inst>,
    /// Where a match starts.
    entry: usize,
    /// The `Accept` instruction: the last one, and never a byte consumer.
    accept: usize,
}

impl Glob {
    /// Compiles a pattern.
    ///
    /// Every byte is accepted, because every byte is either a metacharacter, a
    /// literal, or a literal metacharacter. There is no pattern to reject
    /// here; `compile_glob` in the CLI is where a length bound belongs,
    /// because a bound is a policy and this is a mechanism.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let mut compiler = Compiler {
            program: Vec::with_capacity(pattern.len() + 2),
        };
        let mut at = 0;
        let entry = compiler.sequence(pattern.as_bytes(), &mut at, None, 0);
        compiler.emit(Inst::Accept);
        let accept = compiler.program.len() - 1;
        Self {
            program: compiler.program,
            entry,
            accept,
        }
    }

    /// Whether the pattern matches the whole path.
    ///
    /// Every live instruction is offered each byte, the survivors move on, and
    /// the new set is closed over the zero-width instructions. `accept` is
    /// outside the loop, which is what makes `index + 1` in bounds and what
    /// keeps the simulation from needing a retry.
    #[must_use]
    pub fn is_match(&self, path: &str) -> bool {
        let width = self.program.len();
        let mut live = vec![false; width];
        let mut following = vec![false; width];
        let mut pending = Vec::with_capacity(width);
        live[self.entry] = true;
        self.close(&mut live, &mut pending);
        for &byte in path.as_bytes() {
            following.fill(false);
            let mut survivors = false;
            for index in 0..self.accept {
                if live[index] && self.program[index].consumes(byte) {
                    following[index + 1] = true;
                    survivors = true;
                }
            }
            if !survivors {
                return false;
            }
            self.close(&mut following, &mut pending);
            std::mem::swap(&mut live, &mut following);
        }
        live[self.accept]
    }

    /// Conservative upper bound on matcher instruction/path-byte pairs.
    pub(crate) fn work_bound(&self, path_bytes: usize) -> Option<usize> {
        self.program.len().checked_mul(path_bytes)
    }

    /// Extends a set of live instructions over the zero-width ones.
    ///
    /// A worklist rather than a single sweep, because the zero-width edges do
    /// not all point forwards: the `*` loop goes back to its own head, so a
    /// state can become live *after* the sweep has walked past it. Each
    /// instruction is therefore queued once and expanded once, which is what
    /// bounds this at the width of the program and what makes it terminate
    /// even though the program has loops in it.
    fn close(&self, set: &mut [bool], pending: &mut Vec<usize>) {
        pending.clear();
        pending.extend(
            set.iter()
                .enumerate()
                .filter_map(|(index, on)| on.then_some(index)),
        );
        let mut at = 0;
        while let Some(index) = pending.get(at).copied() {
            at += 1;
            let Some((first, second)) = self.program[index].edges() else {
                continue;
            };
            for target in [first, second] {
                if !set[target] {
                    set[target] = true;
                    pending.push(target);
                }
            }
        }
    }
}

struct Compiler {
    program: Vec<Inst>,
}

impl Compiler {
    fn emit(&mut self, inst: Inst) -> usize {
        let index = self.program.len();
        self.program.push(inst);
        index
    }

    /// Compiles one run of terms and returns where a match enters it.
    ///
    /// `close` is the `}` ending the enclosing alternation, or `None` at the
    /// top level -- which is what makes a top-level comma an ordinary byte and
    /// a comma inside `{...}` a separator. `depth` is the brace nesting, so
    /// `{a,{b,c}}` nests rather than flattening into one alternation.
    ///
    /// The returned entry is the jump emitted before the body, filled in with
    /// the body's own first instruction, or with the end when the body is
    /// empty. An empty run still needs somewhere to stand -- `{,a}` has a
    /// branch that matches the empty string -- and emitting the jump first is
    /// what makes that entry the very next instruction, so a caller's idea of
    /// where this run starts stays true.
    fn sequence(
        &mut self,
        pattern: &[u8],
        at: &mut usize,
        close: Option<usize>,
        depth: usize,
    ) -> usize {
        let entry = self.emit(Inst::Jump(0));
        let body = self.program.len();
        // A comma ends a branch only inside a group. At the top level it is an
        // ordinary byte, because a pattern with no braces in it has no branch
        // to end -- and `Root/[{]a,b[}]` is a title with a comma in it.
        let in_group = close.is_some();
        while *at < pattern.len() && Some(*at) != close && !(in_group && pattern[*at] == b',') {
            self.term(pattern, at, depth);
        }
        let end = self.program.len();
        self.program[entry] = Inst::Jump(if body == end { end } else { body });
        entry
    }

    /// Compiles one metacharacter, or one literal byte.
    fn term(&mut self, pattern: &[u8], at: &mut usize, depth: usize) {
        match pattern[*at] {
            b'*' => self.star(pattern, at),
            b'?' => {
                *at += 1;
                self.emit(Inst::Any);
            }
            b'[' => {
                if !self.class(pattern, at) {
                    *at += 1;
                    self.emit(Inst::Byte(b'['));
                }
            }
            b'{' => {
                if !self.alternation(pattern, at, depth) {
                    *at += 1;
                    self.emit(Inst::Byte(b'{'));
                }
            }
            byte => {
                *at += 1;
                self.emit(Inst::Byte(byte));
            }
        }
    }

    /// Compiles a run of one or more `*`.
    ///
    /// Two or more followed by `/` is `**/`: zero or more whole path groups.
    /// That is the one place consecutive stars change their old meaning, and
    /// only because there is no other way to write it -- `Root/**/admin` did
    /// not match `Root/admin` before, since the old crossing `*` is what made
    /// the separator mandatory. Everywhere else a run is one star, and `*` is
    /// byte-oriented and separator-crossing, so `a**b` still matches `a/X/Yb`.
    fn star(&mut self, pattern: &[u8], at: &mut usize) {
        let mut run = 0;
        while pattern.get(*at + run) == Some(&b'*') {
            run += 1;
        }
        if run >= 2 && pattern.get(*at + run) == Some(&b'/') {
            *at += run + 1;
            // (`[^/]*` `/`)* in six instructions, whatever surrounds it:
            //
            //   0  take a group, or leave
            //   1  another byte of this group, or the separator
            //   2  a byte that is not a separator
            //   3  ...so back for another byte of this group
            //   4  the separator, which ends this group
            //   5  ...so back for another group
            //
            // The exit is the next instruction, so the fragment needs no
            // patching. The inner loop is what makes a group of more than one
            // byte work: a single non-separator byte would read one byte and
            // then require the separator, so `**/` would span one-letter
            // groups only.
            let head = self.program.len();
            self.emit(Inst::Split(head + 1, head + 6));
            self.emit(Inst::Split(head + 2, head + 4));
            self.emit(Inst::AnyNotSlash);
            self.emit(Inst::Jump(head + 1));
            self.emit(Inst::Byte(b'/'));
            self.emit(Inst::Jump(head));
        } else {
            *at += run;
            // A loop that takes a byte and comes back: any number of bytes,
            // including none. Two details are load-bearing. The loop cannot be
            // a self-reaching `Split` alone, because a `Split` that consumes
            // nothing would accept the empty string and then be stuck -- it
            // could never read the byte that keeps it in the loop. And its exit
            // is the instruction *after* it rather than the end of the run,
            // because `*a` has to go on to match the `a`.
            let head = self.program.len();
            self.emit(Inst::Split(head + 1, head + 3));
            self.emit(Inst::Any);
            self.emit(Inst::Jump(head));
        }
    }

    /// Compiles `{a,b,c}`, entered at the first choice.
    ///
    /// `false` -- and the `{` left as a literal byte -- unless the brace is
    /// balanced, is not nested too deeply, and holds a comma of its own. A
    /// brace with nothing to choose between is not a choice, so `{db}` stays
    /// the three bytes it has always been and a title containing braces stays
    /// findable without any quoting convention to learn.
    ///
    /// Every choice is emitted before any branch, because a choice has to be a
    /// choice: a split written after the first branch's own code is reached
    /// only by having matched that branch, which makes the group a sequence
    /// rather than an alternation. The first split is the first instruction of
    /// the enclosing run, so the enclosing run enters the alternation without
    /// having to know one was compiled here.
    fn alternation(&mut self, pattern: &[u8], at: &mut usize, depth: usize) -> bool {
        if depth >= MAX_BRACE_DEPTH {
            return false;
        }
        let Some(close) = brace_end(pattern, *at) else {
            return false;
        };
        let branches = branch_count(&pattern[*at + 1..close]);
        if branches < 2 {
            return false;
        }
        let splits: Vec<usize> = (0..branches - 1)
            .map(|_| self.emit(Inst::Split(UNSET, UNSET)))
            .collect();
        *at += 1; // the brace
        let mut starts = Vec::with_capacity(branches);
        let mut leaves = Vec::with_capacity(branches - 1);
        for branch in 0..branches {
            starts.push(self.sequence(pattern, at, Some(close), depth + 1));
            if branch + 1 < branches {
                leaves.push(self.emit(Inst::Jump(UNSET)));
                *at += 1; // the comma
            }
        }
        // A branch that matched goes on to whatever follows the alternation,
        // which is the very next instruction -- not the branch the loop above
        // just wrote, and not the end of the enclosing run either, which would
        // skip every term after this one.
        let end = self.program.len();
        for (index, split) in splits.iter().enumerate() {
            // A split offers the next branch, and a branch but the last offers
            // the split after it rather than the branch: a chain, so that
            // choosing the second branch does not require having reached the
            // first one's code.
            let next = splits
                .get(index + 1)
                .copied()
                .unwrap_or(starts[branches - 1]);
            self.program[*split] = Inst::Split(starts[index], next);
        }
        for leaf in &leaves {
            self.program[*leaf] = Inst::Jump(end);
        }
        *at = close + 1;
        true
    }

    /// Compiles `[abc]`, `[a-z]`, `[!a-z]`, `[^a-z]` and `[]a]`.
    ///
    /// `false` when there is no closing `]`, and the `[` is then a literal
    /// byte. `globset` makes that a hard error, which would turn a pattern
    /// that works today into a failure; here the byte is a byte.
    ///
    /// Ranges are over bytes, like everything else here. A multi-byte
    /// character has to be written out, because a byte set has no room to
    /// hold one and pretending otherwise would make `[é]` match the first byte
    /// of `é` and then fail on the second.
    fn class(&mut self, pattern: &[u8], at: &mut usize) -> bool {
        let mut bits = [0_u64; 4];
        let mut index = *at + 1;
        let negated = matches!(pattern.get(index), Some(b'!' | b'^'));
        if negated {
            index += 1;
        }
        // A `]` in first position is a member rather than the end, without
        // which `[]a]` -- the class of a `]` and an `a` -- reads as unclosed.
        if pattern.get(index) == Some(&b']') {
            add_to_set(&mut bits, b']');
            index += 1;
        }
        loop {
            let Some(&low) = pattern.get(index) else {
                return false;
            };
            index += 1;
            if low == b']' {
                break;
            }
            // `a-z` is a range; a `-` before the closing `]` is a member, so
            // `[a-]` is `a` and `-`.
            let high = match (pattern.get(index), pattern.get(index + 1)) {
                (Some(&b'-'), Some(&end)) if end != b']' => {
                    index += 2;
                    Some(end)
                }
                _ => None,
            };
            match high {
                Some(end) if low <= end => {
                    for byte in low..=end {
                        add_to_set(&mut bits, byte);
                    }
                }
                // A reversed range such as `[z-a]` cannot mean a range, so it
                // keeps the three bytes it was written with rather than
                // quietly matching nothing at all.
                Some(end) => {
                    add_to_set(&mut bits, low);
                    add_to_set(&mut bits, b'-');
                    add_to_set(&mut bits, end);
                }
                None => add_to_set(&mut bits, low),
            }
        }
        *at = index;
        self.emit(Inst::Class { bits, negated });
        true
    }
}

/// The `}` closing the `{` at `open`, if there is one.
///
/// A bracket opens a class, so a brace inside one is a member and not a
/// nesting level: `[}]` is a class, and treating its `}` as the end of a group
/// would send the scanner after a `{` that is not there.
fn brace_end(pattern: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_usize;
    let mut in_class = false;
    for (offset, &byte) in pattern[open..].iter().enumerate() {
        match byte {
            b'[' => in_class = true,
            b']' => in_class = false,
            b'{' if !in_class => depth += 1,
            b'}' if !in_class => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// How many top-level branches a brace group has: one more than its commas.
///
/// One -- meaning "not an alternation at all", so `{db}` is the three bytes it
/// has always been -- unless the group holds a comma of its own. A comma
/// inside a class is a member, and a comma inside a nested group belongs to
/// that group: `{a{b,c}}` is one branch containing an alternation, and
/// `{a,[b,c]}` is one branch containing a class.
fn branch_count(group: &[u8]) -> usize {
    let mut branches = 1;
    let mut depth = 0_usize;
    let mut in_class = false;
    for &byte in group {
        match byte {
            b'[' => in_class = true,
            b']' => in_class = false,
            b'{' if !in_class => depth += 1,
            b'}' if !in_class => depth = depth.saturating_sub(1),
            b',' if !in_class && depth == 0 => branches += 1,
            _ => {}
        }
    }
    branches
}

#[cfg(test)]
mod tests {
    use super::{Glob, MAX_BRACE_DEPTH};

    /// The matcher this replaced, verbatim.
    ///
    /// It is what the pinned expectations were written against, so keeping it
    /// here turns "the new engine means what the old one meant on old syntax"
    /// from a claim in a commit message into something every run checks -- and
    /// `old_syntax_agrees_with_the_matcher_it_replaced` checks it over a
    /// generated space rather than over a list somebody chose.
    fn legacy(pattern: &str, text: &str) -> bool {
        let (p, t) = (pattern.as_bytes(), text.as_bytes());
        let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
        while j < t.len() {
            if i < p.len() && (p[i] == b'?' || p[i] == t[j]) {
                i += 1;
                j += 1;
            } else if i < p.len() && p[i] == b'*' {
                star = Some(i);
                i += 1;
                retry = j;
            } else if let Some(s) = star {
                i = s + 1;
                retry += 1;
                j = retry;
            } else {
                return false;
            }
        }
        p[i..].iter().all(|c| *c == b'*')
    }

    /// The engine under test, spelled the way a caller spells it.
    fn compiled(pattern: &str, path: &str) -> bool {
        Glob::new(pattern).is_match(path)
    }

    /// Every word over `alphabet` up to `max_len` bytes, shortest first.
    fn every_word(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let longer: Vec<Vec<u8>> = frontier
                .iter()
                .flat_map(|word| {
                    alphabet.iter().map(move |&byte| {
                        let mut extended = word.clone();
                        extended.push(byte);
                        extended
                    })
                })
                .collect();
            words.extend(longer.iter().cloned());
            frontier = longer;
        }
        words
    }

    /// Asserts the engine and the old matcher agree on every old-syntax pair,
    /// and reports how many pairs that was so a broken generator cannot leave
    /// the test passing by checking nothing.
    fn assert_agrees(patterns: &[Vec<u8>], paths: &[Vec<u8>]) {
        let mut checked = 0_usize;
        for pattern in patterns {
            if !is_old_syntax(pattern) {
                continue;
            }
            let pattern = String::from_utf8(pattern.clone()).expect("generated pattern is ASCII");
            let compiled = Glob::new(&pattern);
            for path in paths {
                let path = String::from_utf8(path.clone()).expect("generated path is ASCII");
                assert_eq!(
                    compiled.is_match(&path),
                    legacy(&pattern, &path),
                    "pattern {pattern:?} against path {path:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 100_000, "only {checked} pairs were checked");
    }

    /// Whether a pattern is written in the syntax that existed before the
    /// engine moved, which is the only syntax the old matcher can be compared
    /// against: no class, no alternation, and no `**` in front of a separator.
    ///
    /// The generated spaces hold `*` and `/` together, so they do produce
    /// `**/`, and those are the one old-syntax-shaped pattern the new meaning
    /// deliberately changes. They are excluded here and pinned by name in
    /// `new_syntax_changes_only_well_formed_brackets_and_braces`.
    fn is_old_syntax(pattern: &[u8]) -> bool {
        if pattern.contains(&b'[') || pattern.contains(&b'{') {
            return false;
        }
        for (at, byte) in pattern.iter().enumerate() {
            if *byte != b'*' {
                continue;
            }
            let run = pattern[at..]
                .iter()
                .take_while(|next| **next == b'*')
                .count();
            if run >= 2 && pattern.get(at + run) == Some(&b'/') {
                return false;
            }
        }
        true
    }

    #[test]
    fn glob_matches_paths() {
        assert!(compiled("Root/*/mail?", "Root/Work/mail1"));
        assert!(!compiled("Root/*/mail?", "Root/Work/mail12"));
    }

    /// The contract, and the reason the engine is written the way it is.
    #[test]
    fn pinned_glob_semantics_are_preserved() {
        // `*` crosses the separator. This is the load-bearing case: a group
        // path is one string, so `Root/*` has always meant "any depth".
        assert!(compiled("Root/*", "Root/Work/mail1"));
        assert!(compiled("*", "a/b/c"));
        assert!(compiled("Root/Work*", "Root/Work/mail1"));
        assert!(compiled("Root/*/mail*", "Root/Work/Team/mail1"));
        assert!(compiled("*/mail1", "Root/Work/mail1"));
        assert!(compiled("*Root*", "x/Root/y"));
        assert!(!compiled("Root/*", "Root"));
        assert!(!compiled("Root/*", "Other/Work/mail1"));

        // Consecutive stars are still stars. `**` only becomes a recursive
        // component matcher when a `/` follows it, so a `**` with a literal
        // on either side keeps its old meaning.
        assert!(compiled("a**b", "aXXb"));
        assert!(compiled("a**b", "a/X/b"));
        assert!(compiled("***", "anything/at/all"));
        assert!(compiled("**", "a/b"));
        assert!(compiled("Root/**", "Root/a/b"));
        assert!(compiled("a**b", "a/X/Yb"));

        // `?` is one *byte*, and a byte is a byte.
        assert!(compiled("Roo?", "Root"));
        assert!(compiled("?", "/"));
        // A `?` in the middle consumes the separator byte like any other, so
        // it eats a byte and leaves a byte nothing else can match.
        assert!(compiled("Root?", "Root/"));
        assert!(!compiled("Root?", "Root/a"));
        assert!(compiled("mail?", "mail1"));
        assert!(compiled("*?", "a"));
        assert!(compiled("?*", "a"));
        assert!(!compiled("mail?", "mail12"));
        assert!(!compiled("mail?", "mail"));
        assert!(!compiled("?", ""));
        assert!(!compiled("*?*", ""));
        // The awkward half of byte-oriented: one byte of a two-byte character
        // is not a character, so `?` cannot match `é` and cannot match its
        // first byte either, because the second byte is left over.
        assert!(!compiled("?", "é"));
        assert!(!compiled("caf?", "café"));
        assert!(compiled("caf*", "café"));
        assert!(compiled("*é", "café"));

        // Empty is a pattern like any other, not "match everything".
        assert!(compiled("", ""));
        assert!(compiled("*", ""));
        assert!(compiled("a*", "a"));
        assert!(!compiled("", "a"));
        assert!(!compiled("a", ""));

        // No metacharacters at all: an exact, case-sensitive comparison.
        assert!(compiled("Root/Work/mail1", "Root/Work/mail1"));
        assert!(!compiled("Root/Work", "Root/Work/mail1"));
        assert!(!compiled("Root", "Root/a"));
        assert!(!compiled("root/*", "Root/a"));
        assert!(!compiled("ROOT", "Root"));

        // Regex-significant bytes in a title are ordinary characters.
        assert!(compiled("a.b", "a.b"));
        assert!(!compiled("a.b", "axb"));
        assert!(compiled("a+b", "a+b"));
        assert!(!compiled("a+b", "aaab"));
        assert!(compiled("a|b", "a|b"));
        assert!(!compiled("a|b", "ab"));
        assert!(compiled("(a)", "(a)"));
        assert!(!compiled("(a)", "a"));
        assert!(compiled("a$", "a$"));
        assert!(compiled("a^b", "a^b"));
        assert!(compiled("a{b", "a{b"));
        assert!(compiled("a}b", "a}b"));

        // A backslash is not an escape. Adding one would retarget every
        // existing pattern that happens to contain one.
        assert!(compiled("a\\b", "a\\b"));
        assert!(!compiled("a\\b", "ab"));

        // The new syntax must not swallow the old meaning of a bracket or a
        // brace that never formed a class or an alternation. A well-formed
        // `[1]` and a `{a,b}` do change meaning, and that is a deliberate,
        // separately pinned change.
        assert!(compiled("web[1", "web[1"));
        assert!(!compiled("web[1", "web1"));
        assert!(compiled("web]1", "web]1"));
        assert!(compiled("{db}", "{db}"));
        assert!(!compiled("{db}", "db"));
        assert!(compiled("a{2}", "a{2}"));
    }

    /// The same property, over every short pattern rather than a chosen few.
    ///
    /// Two alphabets: one is the syntax that matters -- `*`, `?` and the
    /// separator -- and the other is the set of bytes a title can contain that
    /// a regex would have treated as structure. Neither holds `[` or `{`, so
    /// every pattern here is old syntax, which is the whole claim.
    #[test]
    fn old_syntax_agrees_with_the_matcher_it_replaced() {
        assert_agrees(&every_word(b"ab/*?", 4), &every_word(b"ab/", 5));
        assert_agrees(&every_word(b"a.+]$^()\\|", 3), &every_word(b"a.+\\/", 4));
    }

    #[test]
    fn alternation_takes_every_branch() {
        assert!(compiled("Root/{prod,staging}/*", "Root/prod/db"));
        assert!(compiled("Root/{prod,staging}/*", "Root/staging/db"));
        assert!(!compiled("Root/{prod,staging}/*", "Root/dev/db"));
        // More than two branches, and branches that are themselves patterns.
        assert!(compiled("Root/{a,b,c}/db", "Root/c/db"));
        assert!(compiled("{a,{b,c}}", "c"));
        assert!(compiled("{a,{b,c}}", "b"));
        assert!(!compiled("{a,{b,c}}", "d"));
        // An empty branch matches the empty string, and a star still crosses.
        assert!(compiled("x{,y}z", "xz"));
        assert!(compiled("x{,y}z", "xyz"));
        assert!(compiled("{x,y}Root", "yRoot"));
        assert!(compiled("{*,x}Root", "a/b/Root"));
    }

    #[test]
    fn globstar_spans_zero_or_more_groups() {
        assert!(compiled("Root/**/admin", "Root/admin"));
        assert!(compiled("Root/**/admin", "Root/a/admin"));
        assert!(compiled("Root/**/admin", "Root/a/b/c/admin"));
        assert!(!compiled("Root/**/admin", "Rootx/admin"));
        assert!(!compiled("Root/**/admin", "Root/a/b/administrator"));
        // A `**` is only recursive before a separator. Anywhere else it is the
        // crossing star it has always been, and a trailing one still needs the
        // separator that precedes it.
        assert!(compiled("Root/**", "Root/a/b"));
        assert!(!compiled("Root/**", "Root"));
        assert!(compiled("a/**/b", "a/b"));
    }

    #[test]
    fn classes_are_byte_sets() {
        assert!(compiled("[a-z]x", "bx"));
        assert!(!compiled("[a-z]x", "Bx"));
        assert!(compiled("[^a-z]x", "Bx"));
        assert!(!compiled("[^a-z]x", "bx"));
        assert!(compiled("[!a-z]x", "Bx"));
        assert!(compiled("[a-cx-z]", "y"));
        assert!(compiled("[]a]", "]"));
        assert!(compiled("[a-]", "-"));
        assert!(compiled("[a-]", "a"));
        // A multi-byte character is two bytes, and a class holds one, so it
        // does not match the character. `globset` agrees, which is why the byte
        // semantics of `?` were cheap to keep.
        assert!(!compiled("[é]", "é"));
        // A reversed range cannot be a range, so it keeps the three bytes it
        // was written with instead of quietly matching nothing.
        assert!(compiled("[z-a]", "z"));
        assert!(compiled("[z-a]", "-"));
        assert!(!compiled("[z-a]", "z-a"));
    }

    /// The three places old syntax did change meaning, on purpose.
    ///
    /// A well-formed `[...]` or `{a,b}` cannot be read as the bytes it is
    /// written with and also be a class or an alternation, so these patterns
    /// are new syntax the moment they are well-formed. A vault title
    /// containing them is now matched by quoting it as a class of its own
    /// bytes -- `web[1]` is matched by `web[[]1[]]` -- which is why the
    /// unclosed forms above stay literal rather than erroring.
    #[test]
    fn new_syntax_changes_only_well_formed_brackets_and_braces() {
        assert!(compiled("web[1]", "web1"));
        assert!(!compiled("web[1]", "web[1]"));
        assert!(compiled("web[[]1[]]", "web[1]"));
        assert!(compiled("Root/{a,b}", "Root/a"));
        assert!(!compiled("Root/{a,b}", "Root/{a,b}"));
        assert!(compiled("Root/{{a,b}}", "Root/{a}"));
        assert!(compiled("Root/[{]a,b[}]", "Root/{a,b}"));
        // `**/` is the third: it has no old spelling at all.
        assert!(!legacy("Root/**/admin", "Root/admin"));
        assert!(compiled("Root/**/admin", "Root/admin"));
    }

    /// The bounds, as a test rather than as a claim.
    ///
    /// Every case here is one an expanding matcher would not survive: a
    /// hundred two-way groups is 2^100 patterns, and a matcher that retries
    /// instead of simulating takes exponential time on `*a*a*a*a*b` against
    /// a long run of `a`. There is no timing assertion here on purpose -- a
    /// matcher with those costs does not return, so completing *is* the
    /// assertion, and a test that waits for a timeout is a test that fails
    /// without explaining.
    #[test]
    fn pathological_patterns_stay_bounded() {
        let groups = "{a,b}".repeat(100);
        let branches = Glob::new(&format!("x{groups}"));
        assert!(branches.is_match(&format!("x{}", "ab".repeat(50))));
        assert!(!branches.is_match(&format!("x{}z", "ab".repeat(50))));

        // A pattern longer than the longest path it can match, so nothing
        // short-circuits and every byte of the text is offered to every
        // instruction.
        let wide = Glob::new(&"*a".repeat(500));
        assert!(wide.is_match(&"a".repeat(4096)));
        assert!(!wide.is_match(&format!("{}b", "a".repeat(4096))));

        // Nesting past the depth bound stops compiling braces rather than
        // recursing further, so the pattern stops meaning what the nesting
        // would have said -- and the compiler returned at all.
        let deep = format!(
            "{}b{}",
            "{a,".repeat(MAX_BRACE_DEPTH + 8),
            "}".repeat(MAX_BRACE_DEPTH + 8)
        );
        assert!(!Glob::new(&deep).is_match("ab"));

        // The depth bound is a constant of this module, not a coincidence
        // with the pattern-length limit, so a pattern inside the length limit
        // cannot nest its way past it.
        let within = format!(
            "{}a{}",
            "{".repeat(MAX_BRACE_DEPTH + 1),
            "}".repeat(MAX_BRACE_DEPTH + 1)
        );
        assert!(!Glob::new(&within).is_match("a"));
    }

    /// A deep tree, at the shape one really has: many paths, one pattern, one
    /// compilation.
    ///
    /// The cost per path is the simulation and nothing else, so the whole walk
    /// is linear in the number of paths -- which is why the pattern is
    /// compiled before the walk rather than inside it.
    #[test]
    fn a_deep_tree_is_one_simulation_per_path() {
        let pattern = Glob::new("Root/**/admin-*");
        let mut matched = 0_usize;
        for group in 0..2_000 {
            let path = format!("Root/{group}/{group}/{group}/admin-{group}");
            if pattern.is_match(&path) {
                matched += 1;
            }
        }
        assert_eq!(matched, 2_000);
    }
}
