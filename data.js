window.BENCHMARK_DATA = {
  "lastUpdate": 1782446020891,
  "repoUrl": "https://github.com/BorrowSanitizer/bsan",
  "entries": {
    "Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T10:49:04-04:00",
          "tree_id": "23331ef1e91a24f03cb4322b1fcf757c20b10252",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782403856774,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1543.0793929315814,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32430.730225402294, \"min\": 681.5370927265737}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23988261596451257,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8704847731132409, \"min\": 0.06769690664783796}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.44273554714767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.980751120959804, \"min\": 6.3101221009895285}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017238213404355285,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0020928322177737975, \"min\": 0.0002751156814834583}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1504.2099542175135,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 29562.69291589114, \"min\": 547.4114307605067}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2859837376422489,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9498733585969336, \"min\": 0.07144842411021436}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.003153436662792,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.36397963349311, \"min\": 6.4477904584222525}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0029846382991930136,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0038394961270337797, \"min\": 0.0006777935131860332}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "fbc2fc1818d1be92a27483aa5850e686dc8867f3",
          "message": "Remove `indexmap`.",
          "timestamp": "2026-06-25T14:49:04Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fbc2fc1818d1be92a27483aa5850e686dc8867f3"
        },
        "date": 1782446020532,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1543.1755119743298,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32993.60154328943, \"min\": 640.4652443348723}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2402245146962659,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9073288805474994, \"min\": 0.06558033556108486}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.286690683703089,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.497205690406837, \"min\": 5.46010249811506}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017064301089244074,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0022571884845015867, \"min\": 0.0002441079836429678}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 2038.7212325874777,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 41603.25416571118, \"min\": 998.6590075957778}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.3056084048120172,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.7811470655512245, \"min\": 0.06236720824802958}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 8.766662188946627,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 26.73244623186731, \"min\": 6.703016387667619}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0018984005253323186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0023611562165052175, \"min\": 0.0002721114587116341}"
          }
        ]
      }
    ]
  }
}