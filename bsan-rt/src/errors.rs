use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::max;

use hashbrown::HashMap;

use crate::helpers::Size;
use crate::sanitizer_common::{SanitizerCommon, Symbol};
use crate::tree_borrows::diagnostics::TreeBorrowsUb;
use crate::AllocId;

pub enum UBInfo {
    AccessOutOfBounds { alloc_id: AllocId, access_size: Size, offset: Size, alloc_size: Size },
    UseAfterFree,
    AliasingViolation(TreeBorrowsUb),
}

impl From<TreeBorrowsUb> for UBInfo {
    fn from(value: TreeBorrowsUb) -> Self {
        UBInfo::AliasingViolation(value)
    }
}

pub type UBResult<T> = Result<T, UBInfo>;

#[derive(Default)]
pub struct ErrorFormatContext {
    file_cache: HashMap<String, String>,
}

impl ErrorFormatContext {
    pub fn display_ub(&mut self, info: UBInfo, symbol: Symbol, origin: Option<Symbol>) -> String {
        let mut result = String::new();
        result.push_str("Undefined Behavior: ");
        match info {
            UBInfo::UseAfterFree => {
                result.push_str("trying to access an allocation that has been freed.\n");
                result.push_str(&self.format_symbol_standalone(symbol));
                result.push_str(&self.format_origin(origin, None));
                result.push('\n');
            }
            UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset } => {
                result.push_str(&format!(
                    "an access of size {access_size:x}b at offset 0x{offset:x} is out of bounds for {alloc_id:?} of size {alloc_size:x}b.\n"
                ));
                result.push_str(&self.format_symbol_standalone(symbol));
                result.push_str(&self.format_origin(origin, None));
                result.push('\n');
            }
            UBInfo::AliasingViolation(error) => {
                result.push_str(&self.display_tree_error(error, symbol, origin))
            }
        }
        result
    }

    /// Renders the origin note pointing at the immediate library site
    fn format_origin(&mut self, origin: Option<Symbol>, max_indent: Option<usize>) -> String {
        match origin {
            Some(origin) => {
                let mut buffer = String::new();
                buffer.push_str("note: this bug originates from a call to library code, here:\n");
                buffer.push_str(&match max_indent {
                    Some(indent) => self.format_symbol(origin, indent),
                    None => self.format_symbol_standalone(origin),
                });
                buffer
            }
            None => String::new(),
        }
    }

    fn display_tree_error(
        &mut self,
        mut error: TreeBorrowsUb,
        symbol: Symbol,
        origin: Option<Symbol>,
    ) -> String {
        let mut buffer = String::new();

        let mut max_indentation = symbol.line_length();
        let event_symbols: Vec<(Option<Symbol>, String)> = error
            .history
            .events
            .drain(..)
            .map(|evt| {
                if let Some(span) = evt.0 {
                    let sym = SanitizerCommon::symbolize(span);
                    max_indentation = max_indentation.max(sym.line_length());
                    (Some(sym), evt.1)
                } else {
                    (None, evt.1)
                }
            })
            .collect();

        if let Some(origin) = &origin {
            max_indentation = max_indentation.max(origin.line_length());
        }

        buffer.push_str(&error.title);
        buffer.push('\n');

        buffer.push_str(&self.format_symbol(symbol, max_indentation));

        buffer.push_str(&self.format_origin(origin, Some(max_indentation)));

        for detail in error.details {
            buffer.push_str(&format!("{} = help: {}\n", " ".repeat(max_indentation), detail));
        }

        for (symbol, msg) in event_symbols {
            if let Some(symbol) = symbol {
                buffer.push_str(&format!("help: {}\n", msg));
                buffer.push_str(&self.format_symbol(symbol, max_indentation));
            } else {
                buffer.push_str(&format!("{} = help: {}\n", " ".repeat(max_indentation), msg));
            }
        }
        buffer.push('\n');
        buffer
    }

    fn format_symbol_standalone(&mut self, symbol: Symbol) -> String {
        let length = symbol.line_length();
        self.format_symbol(symbol, length)
    }

    fn format_symbol(&mut self, symbol: Symbol, indentation: usize) -> String {
        let mut buffer = String::new();
        match symbol {
            Symbol::Resolved { file: path, line, col } => {
                let max_indent = " ".repeat(indentation);
                buffer.push_str(&format!("{max_indent}--> {path}:{line}:{col}\n"));
                let file = self
                    .file_cache
                    .entry(path.clone())
                    .or_insert_with(|| SanitizerCommon::read_file(&path).unwrap_or_default());
                if let Some(content) = SanitizerCommon::get_source_line(file, line) {
                    let line = line.to_string();
                    let line_indent_len = max(indentation, line.len()) - line.len();
                    let line_indent = " ".repeat(line_indent_len);

                    buffer.push_str(&format!("{max_indent} |\n",));
                    buffer.push_str(&format!("{line_indent}{line} | {content}\n"));
                    buffer.push_str(&format!("{max_indent} |\n",));
                }
            }
            Symbol::Unresolved { pc } => {
                buffer.push_str(&format!(" --> 0x{pc:x}\n"));
            }
            Symbol::Unused => (),
        }
        buffer
    }
}
