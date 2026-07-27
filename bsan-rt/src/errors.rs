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
        let mut result = String::from("Undefined Behavior: ");
        let message = match info {
            UBInfo::UseAfterFree => {
                "trying to access an allocation that has been freed.\n".to_string()
            }
            UBInfo::AccessOutOfBounds { alloc_id, access_size, alloc_size, offset } => format!(
                "an access of size {access_size:x}b at offset 0x{offset:x} is out of bounds for {alloc_id:?} of size {alloc_size:x}b.\n"
            ),
            UBInfo::AliasingViolation(error) => {
                result.push_str(&self.display_tree_error(error, symbol, origin));
                return result;
            }
        };
        result.push_str(&message);
        result.push_str(&self.format_symbol_standalone(symbol));
        result.push_str(&self.format_origin(origin, None));
        result.push('\n');
        result
    }

    /// Renders the origin note pointing at the immediate library site
    fn format_origin(&mut self, origin: Option<Symbol>, max_indent: Option<usize>) -> String {
        let Some(origin) = origin else {
            return String::new();
        };
        let indent = max_indent.unwrap_or_else(|| origin.line_length());
        let mut buffer = format!(
            "{} = note: the above line calls library code, where the error was detected:\n",
            " ".repeat(indent)
        );
        buffer.push_str(&self.format_symbol(origin, indent));
        buffer
    }

    fn display_tree_error(
        &mut self,
        mut error: TreeBorrowsUb,
        symbol: Symbol,
        origin: Option<Symbol>,
    ) -> String {
        let mut buffer = String::new();

        let mut max_indentation = symbol.line_length();
        let event_symbols: Vec<(Option<Symbol>, Option<Symbol>, String)> = error
            .history
            .events
            .drain(..)
            .map(|evt| {
                if let Some(span) = evt.0 {
                    let (sym, origin) = SanitizerCommon::symbolize_with_origin(span);
                    max_indentation = max_indentation.max(sym.line_length());
                    if let Some(origin) = &origin {
                        max_indentation = max_indentation.max(origin.line_length());
                    }
                    (Some(sym), origin, evt.1)
                } else {
                    (None, None, evt.1)
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

        for (symbol, origin, msg) in event_symbols {
            if let Some(symbol) = symbol {
                buffer.push_str(&format!("help: {}\n", msg));
                buffer.push_str(&self.format_symbol(symbol, max_indentation));
                buffer.push_str(&self.format_origin(origin, Some(max_indentation)));
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
                if let Some(content_raw) = SanitizerCommon::get_source_line(file, line) {
                    let content = content_raw.trim();
                    let trimmed_ws_diff = content_raw.len() - content.len();

                    let line = line.to_string();
                    let line_indent_len = max(indentation, line.len()) - line.len();
                    let line_indent = " ".repeat(line_indent_len);

                    buffer.push_str(&format!("{max_indent} |\n",));
                    buffer.push_str(&format!("{line_indent}{line} | {content}\n"));

                    let col = col as usize;
                    if trimmed_ws_diff > col {
                        // For some reason, the column offset points into whitespace.
                        // There's an error in the symbolizer or instrumentation that is
                        // beyond our control at this point, so we skip printing the caret.
                        buffer.push_str(&format!("{max_indent} |\n",));
                    } else {
                        let offset = col.saturating_sub(trimmed_ws_diff).saturating_sub(1);
                        let column_repeat = " ".repeat(offset);
                        buffer.push_str(&format!("{max_indent} | {column_repeat}^\n",));
                    }
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
