[![CI](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml/badge.svg)](https://github.com/BorrowSanitizer/bsan/actions/workflows/ci.yml) [![docs](https://github.com/borrow-sanitizer/docs/actions/workflows/docs.yml/badge.svg)](https://borrowsanitizer.com) [![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://bsan.zulipchat.com/) [![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/BorrowSanitizer/bsan)

# <a href="https://borrowsanitizer.com"><img height="50px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href="https://github.com/verus-lang/verus"><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

BorrowSanitizer is work-in-progress LLVM instrumentation pass for detecting aliasing violations in multi-language Rust applications. Our project is still in early stages, but our goal is to support detecting the following types of errors:
* Violations of Rust's [*Tree Borrows*](https://perso.crans.org/vanille/treebor/) aliasing model.
* Accesses out-of-bounds
* Use-after free errors.

For more information, check out [our website](https://borrowsanitizer.com).

---
BorrowSanitizer is dual-licensed under [Apache](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-APACHE) and [MIT](https://github.com/BorrowSanitizer/bsan/blob/main/LICENSE-MIT), following the Rust project.

[<img src="https://borrowsanitizer.com/images/zulip-icon-circle.svg" alt="Zulip" style="height: 1em;"/> Zulip](https://zulip.com/) sponsors free hosting for BorrowSanitizer. Zulip is an organized team chat app designed for efficient communication.
