use alloc::string::{String, ToString};
use core::cmp::max;

use hashbrown::HashMap;

use crate::sanitizer_common::{SanitizerCommon, Span, Symbol};
use crate::tree_borrows::diagnostics::TreeBorrowsUb;
use crate::AllocId;

pub enum UBInfo {
    AccessOutOfBounds { alloc_id: AllocId, access_size: usize, offset: usize, alloc_size: usize },
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
    pub fn display_ub(&mut self, info: UBInfo, span: Span) -> String {
        let symbol = SanitizerCommon::symbolize(span);
        let mut result = String::new();
        result.push_str("Undefined Behavior: ");
        match info {
            UBInfo::UseAfterFree => {
                result.push_str("trying to access an allocation that has been freed.\n");
                result.push_str(&self.format_symbol_standalone(symbol));
                result.push('\n');
            }
            UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset } => {
                result.push_str(&format!(
                    "an access of size {access_size}b at offset 0x{offset:x} is out of bounds for {alloc_id:?} of size {alloc_size}b.\n"
                ));
                result.push_str(&self.format_symbol_standalone(symbol));
                result.push('\n');
            }
            UBInfo::AliasingViolation(error) => {
                result.push_str(&self.display_tree_error(error, symbol))
            }
        }
        result
    }

    fn display_tree_error(&mut self, _error: TreeBorrowsUb, _symbol: Symbol) -> String {
        let buffer = String::new();
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
