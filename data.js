window.BENCHMARK_DATA = {
  "lastUpdate": 1781726355660,
  "repoUrl": "https://github.com/BorrowSanitizer/bsan",
  "entries": {
    "Benchmarks": [
      {
        "commit": {
          "author": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "committer": {
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "id": "9f5ac56ff07abdfdb28e4e77bb44a59643403e5a",
          "message": "Upload CSV results too",
          "timestamp": "2026-06-17T19:45:26Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/9f5ac56ff07abdfdb28e4e77bb44a59643403e5a"
        },
        "date": 1781726355236,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 757.0104728167325,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 757.0104728167325, \"min\": 757.0104728167325}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.21892235323718115,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.21892235323718115, \"min\": 0.21892235323718115}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.32617655250295097,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.32617655250295097, \"min\": 0.32617655250295097}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 6.5845526829088055,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 6.5845526829088055, \"min\": 6.5845526829088055}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.001904208488679086,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.001904208488679086, \"min\": 0.001904208488679086}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.002837116223628787,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002837116223628787, \"min\": 0.002837116223628787}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 822.7930772156714,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 822.7930772156714, \"min\": 822.7930772156714}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2577198049800719,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2577198049800719, \"min\": 0.2577198049800719}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.4100176476433057,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4100176476433057, \"min\": 0.4100176476433057}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.263648277198447,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 9.263648277198447, \"min\": 9.263648277198447}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002901611223422786,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002901611223422786, \"min\": 0.002901611223422786}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004616299505174696,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004616299505174696, \"min\": 0.004616299505174696}"
          }
        ]
      }
    ]
  }
}