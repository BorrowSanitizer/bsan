window.BENCHMARK_DATA = {
  "lastUpdate": 1779392871858,
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
          "id": "a51b2a054245056e628fe239856de49509418093",
          "message": "Improved debug output formatting, and ensured latest version for build.",
          "timestamp": "2026-05-21T17:28:55Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/a51b2a054245056e628fe239856de49509418093"
        },
        "date": 1779385007803,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.205,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 6.005,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
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
            "name": "Ian McCormack",
            "username": "icmccorm",
            "email": "icmccorm@cs.cmu.edu"
          },
          "id": "e635859ef2687c9ecbbd3874182d5f7b5f6e3475",
          "message": "Added indexmap.",
          "timestamp": "2026-05-21T17:40:27Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/e635859ef2687c9ecbbd3874182d5f7b5f6e3475"
        },
        "date": 1779387111100,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.17,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.295,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.63,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.805,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
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
          "id": "1b921d5219b2d766f27b94855a965daed455862c",
          "message": "Add a new benchmarking pipeline using `github-action-benchmark` (#184)\n\n* Added script for benchmarking relative execution time.\n\n* Fixed path to config.\n\n* Remove untagged images.\n\n* Merge results.\n\n* Added date formatting.\n\n* versioned file names\n\n* Added date to intermediate artifacts.\n\n* Try out action.\n\n* Try docs.\n\n* Adjust permissions.\n\n* Contents.\n\n* Use gh-pages root.\n\n* .\n\n* rm bencher.sh\n\n* Run on push to main.\n\n* Fix merge.\n\n* Try adding additional fields to the output JSON for better filtering.\n\n* Fixed path.\n\n* Move fields into extra.\n\n* Format extra info as a JSON string.\n\n* Improved debug output formatting, and ensured latest version for build.\n\n* Added indexmap.",
          "timestamp": "2026-05-21T14:35:04-04:00",
          "tree_id": "e88b19e54db522497bb30a2358a2cd56710706aa",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/1b921d5219b2d766f27b94855a965daed455862c"
        },
        "date": 1779389029109,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.84,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.96,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.545,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.845,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7f7aa2bb570a972d17048c17ac35109ebc2d2de6",
          "message": "Get repo stats and check for fixed tests (#187)\n\n* Add metrics command\n\n* print stats tree\n\n* Add top level percents\n\n* xb fix with timeout ish\n\n* fix timeout\n\n* Add fail msg\n\n* Fail message with count\n\n* Kill stuck processes\n\n* Add passing option\n\n* Roll back custom messages\n\n* cherry pick fail msg\n\n* Show tests only with bsan output\n\n* refactor + fix timeout, add aborts\n\n* add mirilli folder",
          "timestamp": "2026-05-21T15:14:22-04:00",
          "tree_id": "199ee1495e9f1d05cd2b3ec6e0da0de7932b3e78",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/7f7aa2bb570a972d17048c17ac35109ebc2d2de6"
        },
        "date": 1779391409062,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.015,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.1,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.615,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.905,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2aa2fd787e41eaf6952b636dcf3ae3b732982f17",
          "message": "Merge pull request #191 from BorrowSanitizer/icmccorm/flate2\n\nAdd UI tests from MiriLLI",
          "timestamp": "2026-05-21T15:23:57-04:00",
          "tree_id": "2e82f60827aaa23d9c9195a573198300258d156c",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/2aa2fd787e41eaf6952b636dcf3ae3b732982f17"
        },
        "date": 1779391989085,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.005,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.3,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.5,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
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
          "id": "ffc58a06dc4ddb796885b06459ad7281b0117443",
          "message": "Rename workflow from 'Bench' to 'Benchmarks'",
          "timestamp": "2026-05-21T15:32:05-04:00",
          "tree_id": "14adc5bda90d3efca0e96417b678ab731c641188",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ffc58a06dc4ddb796885b06459ad7281b0117443"
        },
        "date": 1779392490361,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.93,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.055,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.485,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.57,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
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
          "id": "d00f24be91375023f690cd5c5d01659aa5e729c9",
          "message": "Added \"Benchmarks\" status badge",
          "timestamp": "2026-05-21T15:33:25-04:00",
          "tree_id": "a37aa2fafe3ceaed97a60856b4f9001de6f23832",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/d00f24be91375023f690cd5c5d01659aa5e729c9"
        },
        "date": 1779392538852,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.695,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.96,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.75,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.71,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "12d00a3ebca02c879458a5d8bf2a46e98262e263",
          "message": "Merge pull request #188 from BorrowSanitizer/icmccorm/quickopt\n\nOnly update the stack pointer if an intrinsic may be cg-ed.",
          "timestamp": "2026-05-21T15:36:22-04:00",
          "tree_id": "127f024567a4e2ce88d608cad17f693adbd1b695",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/12d00a3ebca02c879458a5d8bf2a46e98262e263"
        },
        "date": 1779392727701,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.725,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.91,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.29,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.415,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mojeanmac@gmail.com",
            "name": "Molly MacLaren",
            "username": "mojeanmac"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "23d47878308db14e7bcdc202b9aeb03968569e93",
          "message": "Merge pull request #189 from BorrowSanitizer/icmccorm/prep-wildcard\n\nAvoid treating wildcard provenance as a nop.",
          "timestamp": "2026-05-21T15:38:42-04:00",
          "tree_id": "aa604969589dc2550fd7dc5c334e0288ddf6c46e",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/23d47878308db14e7bcdc202b9aeb03968569e93"
        },
        "date": 1779392871483,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.725,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.95,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.34,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.52,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      }
    ]
  }
}