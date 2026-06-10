window.BENCHMARK_DATA = {
  "lastUpdate": 1781128363187,
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
          "id": "6cbda830c7dc1fcd120c5cca432c98c9a989fc55",
          "message": "Merge pull request #190 from BorrowSanitizer/icmccorm/avoid-array\n\nOnly use a global array for interior mutable ranges when absolutely necessary",
          "timestamp": "2026-05-21T15:43:45-04:00",
          "tree_id": "262fb9df2db8bca4ab2fde6d2f0ca199dcf2a26a",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6cbda830c7dc1fcd120c5cca432c98c9a989fc55"
        },
        "date": 1779393255515,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.855,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.045,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.6850000000000005,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.735,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "6cbda830c7dc1fcd120c5cca432c98c9a989fc55",
          "message": "Merge pull request #190 from BorrowSanitizer/icmccorm/avoid-array\n\nOnly use a global array for interior mutable ranges when absolutely necessary",
          "timestamp": "2026-05-21T19:43:45Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6cbda830c7dc1fcd120c5cca432c98c9a989fc55"
        },
        "date": 1779394136574,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.855,
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
            "value": 5.465,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.575,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Molly MacLaren",
            "username": "mojeanmac",
            "email": "mojeanmac@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "6cbda830c7dc1fcd120c5cca432c98c9a989fc55",
          "message": "Merge pull request #190 from BorrowSanitizer/icmccorm/avoid-array\n\nOnly use a global array for interior mutable ranges when absolutely necessary",
          "timestamp": "2026-05-21T19:43:45Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/6cbda830c7dc1fcd120c5cca432c98c9a989fc55"
        },
        "date": 1779473093688,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.75,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.795,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.38,
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
          "id": "fc4fc78fd77172cb0c289b860488c6ea98fd4922",
          "message": "cargo update + cargo upgrade (#194)",
          "timestamp": "2026-05-22T21:00:17-04:00",
          "tree_id": "5b5e3c4a561f74343afb3b7ae22c19ae27dc4311",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fc4fc78fd77172cb0c289b860488c6ea98fd4922"
        },
        "date": 1779498552471,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.745,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.965,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.465,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.6,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
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
          "id": "91a6ba3f8d928a6fe7861685f61b62c38d627ec4",
          "message": "Added performance alerts.",
          "timestamp": "2026-05-23T17:38:46Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/91a6ba3f8d928a6fe7861685f61b62c38d627ec4"
        },
        "date": 1779559344355,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.21,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.355,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.575,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.58,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b46e290cf2eaf79bbb3c9a2c9e4602387db1d5c8",
          "message": "Instrument variadic arguments (#176)\n\n* feat: track variadic provenance with __bsan_var_arg_ctr\n\n- Add __bsan_var_arg_ctr to bsan-rt and reset on uninstrumented boundary\n- Expose TLS counter in BorrowSanitizer pass\n- Calculate and store vararg count before calls in visitCallBase\n- Allocate shadow stack space for variadics in initStack\n\n* ran xb fmt\n\n* fix(#154): Readded `validate_params` reset and moved `c-variadic.rs` to pass.\n\n* fix(#154): Move test back to should-pass, variadics will be handled in subsequent-pr",
          "timestamp": "2026-05-27T11:25:42-04:00",
          "tree_id": "b809ab7e04a8471be59368ea2acba9942c98211e",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/b46e290cf2eaf79bbb3c9a2c9e4602387db1d5c8"
        },
        "date": 1779896072252,
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
            "value": 5.95,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.48,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.59,
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
          "id": "c56ef2c47ea18980cb0cfc2ff2f0d47722a4f7bd",
          "message": "Ensure that offsets created by `getProvenanceDesc` include struct padding. (#200)",
          "timestamp": "2026-05-27T11:26:08-04:00",
          "tree_id": "f2709c8b3bcd99dbf9d12bcf1211740ee6d78514",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/c56ef2c47ea18980cb0cfc2ff2f0d47722a4f7bd"
        },
        "date": 1779896123427,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.7,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.825,
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
            "value": 5.48,
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
          "id": "507dec6a24d44cbcaef7f5dc11a6e93cb491324e",
          "message": "Merge pull request #195 from BorrowSanitizer/icmccorm/alerts\n\nAdded performance alerts.",
          "timestamp": "2026-05-27T14:36:31-04:00",
          "tree_id": "7fecbf2f6650716ee8c03e66d7e22552f6c7cdc8",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/507dec6a24d44cbcaef7f5dc11a6e93cb491324e"
        },
        "date": 1779907456533,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.895,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.985,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.44,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.59,
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
          "id": "d6c417f0b90f63a2e99edc5db800a187532ab945",
          "message": "Merge pull request #193 from BorrowSanitizer/icmccorm/shadow-skip\n\nAvoid loading and storing the shadow stack pointer.",
          "timestamp": "2026-05-27T17:09:34-04:00",
          "tree_id": "10805f1c04936512790e241de684614a8636aa27",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/d6c417f0b90f63a2e99edc5db800a187532ab945"
        },
        "date": 1779916717077,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.56,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.85,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.575,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.59,
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
          "id": "74a336d53dbe8dfef333ce7eec83c860901b5564",
          "message": "Merge pull request #202 from BorrowSanitizer/icmccorm/perform-pass\n\nMoved tests related to performance into should-pass",
          "timestamp": "2026-05-28T10:20:31-04:00",
          "tree_id": "521118e12b814efcf9ecb86920a02d6581adcd9a",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/74a336d53dbe8dfef333ce7eec83c860901b5564"
        },
        "date": 1779978560239,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.87,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.62,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.755,
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
          "id": "8c2400324a4b5bd3c279b57051755132e2685f21",
          "message": "Added more tests from MiriLLI. (#205)",
          "timestamp": "2026-05-29T11:08:38-04:00",
          "tree_id": "50b667d2c5bac3eafa3016d69f66826c337ff9e3",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/8c2400324a4b5bd3c279b57051755132e2685f21"
        },
        "date": 1780067870127,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.91,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.015,
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
            "value": 5.46,
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
          "id": "99b9364c7d800ec9a4b7c694c6fdb253267f983b",
          "message": "Rely on branching to identify weak overrides (#204)\n\n* Add branch prediction annotations to error handling.\n\n* Rely on branch prediction for weak symbols.",
          "timestamp": "2026-06-01T09:54:28-04:00",
          "tree_id": "5e7122e2efb12a689cb2d6f46ac060ead62e2790",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/99b9364c7d800ec9a4b7c694c6fdb253267f983b"
        },
        "date": 1780322638934,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.81,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.855,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.64,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.135,
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
          "id": "9c0b17c29e5b63c410ecc3138b3636cc5a956a60",
          "message": "Add dedicated \"omnivalid\" provenance. (#203)\n\n* Switched to omnivalid provenance and added taint analysis.\n\n* Update.\n\n* Fixed erroneous renaming.\n\n* Remove taint analysis (for now).\n\n* Rebased.\n\n* fmt",
          "timestamp": "2026-06-01T18:59:12-04:00",
          "tree_id": "fa556e2a6a9b5baee28ac0de0243490e828bd539",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/9c0b17c29e5b63c410ecc3138b3636cc5a956a60"
        },
        "date": 1780355255453,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.395,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.505,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.3,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.425,
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
          "id": "64e715d070699482cc80bd3bd602696da114ce71",
          "message": "Merge pull request #209 from BorrowSanitizer/icmccorm/interception\n\nAdded support for interception.",
          "timestamp": "2026-06-02T15:59:31-04:00",
          "tree_id": "332ebfd3c2f898eb28f97d60262ec1498206dd86",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/64e715d070699482cc80bd3bd602696da114ce71"
        },
        "date": 1780430806802,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.695,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.81,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.79,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.81,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "111544848+vnt1c@users.noreply.github.com",
            "name": "Ryan Hung",
            "username": "vnt1c"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d314c4392abf75d6eb437a8bdff76efe22b768d7",
          "message": "Merge pull request #210 from BorrowSanitizer/vnt1c/lazy-alloc\n\nImplemented Lazy Tree Allocation",
          "timestamp": "2026-06-02T16:41:11-04:00",
          "tree_id": "318469faef356513af26965268e3a8b5e7b2b65b",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/d314c4392abf75d6eb437a8bdff76efe22b768d7"
        },
        "date": 1780433408086,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.735,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.955,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.855,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.985,
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
          "id": "a1854dab15ac8d662d4f09bace96a5cb27f36050",
          "message": "Remove testcrate",
          "timestamp": "2026-06-03T15:02:43-04:00",
          "tree_id": "795d2a0717a92cacf3a4865823af1b051d41aa73",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/a1854dab15ac8d662d4f09bace96a5cb27f36050"
        },
        "date": 1780513920851,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.93,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.86,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.73,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.78,
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
          "id": "a8b8df294644e7d2044a0100c995e0d37d2bf82b",
          "message": "Update workspace exclude list in Cargo.toml\n\nRemoved 'testbed' from the workspace exclude list.",
          "timestamp": "2026-06-03T15:03:05-04:00",
          "tree_id": "c8379e4efb78bf0bab40b593b325fe12af82d1b2",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/a8b8df294644e7d2044a0100c995e0d37d2bf82b"
        },
        "date": 1780513922285,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.605,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.845,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.5649999999999995,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.65,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9a6c78d38d7368f1261aafb355d2e6fdeaed6229",
          "message": "Add smallvec-valmap compile-time feature (#212)",
          "timestamp": "2026-06-03T18:00:54-04:00",
          "tree_id": "5d335edb5b42dba4a2fffb9753c38f55baa05fe2",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/9a6c78d38d7368f1261aafb355d2e6fdeaed6229"
        },
        "date": 1780524575081,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.625,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.725,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.5,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.835,
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
          "id": "0be95a91657d1dc3d2e6813a94edd75caf66aafb",
          "message": "Add and fix passing test(s) (#214)\n\n* add testcase + stats update\n\n* fix annotations",
          "timestamp": "2026-06-04T12:58:42-04:00",
          "tree_id": "d9c028d8992cd1e99e8c29b34a56a4a222702d88",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/0be95a91657d1dc3d2e6813a94edd75caf66aafb"
        },
        "date": 1780592892639,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.65,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.71,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.16,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.385,
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
          "id": "85ffbb682f8327b76a727d173be4b097d2efba41",
          "message": "Fix flaky interceptors test (#216)\n\n* add testcase + stats update\n\n* fix annotations\n\n* flaky interceptors patch\n\n* remove extra check",
          "timestamp": "2026-06-04T13:56:26-04:00",
          "tree_id": "5f1ffd5d42b9900a10e7b6d1d29551d018838bb1",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/85ffbb682f8327b76a727d173be4b097d2efba41"
        },
        "date": 1780596372887,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.59,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.63,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.39,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.51,
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
          "id": "0a770402ca7bf482d9a8e3a0107abdda332152bf",
          "message": "Merge pull request #213 from BorrowSanitizer/icmccorm/wildcard-impl\n\nWildcard Provenance (Part #1)",
          "timestamp": "2026-06-05T10:49:59-04:00",
          "tree_id": "2ce7914f0aeb63681e47833fd4121fce9732b719",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/0a770402ca7bf482d9a8e3a0107abdda332152bf"
        },
        "date": 1780671521308,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.525,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.68,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.98,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.12,
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
          "id": "b539a08991ebb3548c36c618938aafffd48c9795",
          "message": "Merge pull request #217 from BorrowSanitizer/icmccorm/ui-clean\n\nClean our sysroot by default when running UI tests.",
          "timestamp": "2026-06-05T10:53:56-04:00",
          "tree_id": "f5c209e327714bf4370b1bf0cef8695924225e40",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/b539a08991ebb3548c36c618938aafffd48c9795"
        },
        "date": 1780671774614,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.77,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.97,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.705,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.75,
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
          "id": "728619a37b945b7330dc18ccb737cd2f64e110be",
          "message": "Improved formatting of debugging functions. (#219)\n\n* Improved formatting of debugging functions.\n\n* bless",
          "timestamp": "2026-06-08T10:28:26-04:00",
          "tree_id": "f9e5a0edd46a937f4b4fe97c5db9c328e727ec81",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/728619a37b945b7330dc18ccb737cd2f64e110be"
        },
        "date": 1780929423082,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.645,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.85,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.675,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.77,
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
          "id": "b35d54bd72551c34bf2a49650068725be223a477",
          "message": "Merge pull request #220 from BorrowSanitizer/icmccorm/merge\n\nMerge all dependencies of the `BorrowSanitizer` pass into a single file",
          "timestamp": "2026-06-08T10:30:53-04:00",
          "tree_id": "1462fd697f44ba0602bc13742fd80610e99c146c",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/b35d54bd72551c34bf2a49650068725be223a477"
        },
        "date": 1780929609123,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.595,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.66,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.71,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.825,
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
          "id": "ef1224b816d2cbae9615ac42cd45744a02e5f29f",
          "message": "Bump container retention policy to 3.1.0",
          "timestamp": "2026-06-08T12:48:47-04:00",
          "tree_id": "bb69b00195fd43922d57aeb75527c50ad40791c5",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ef1224b816d2cbae9615ac42cd45744a02e5f29f"
        },
        "date": 1780937767719,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.88,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.015,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.73,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.8149999999999995,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "67717700+Gitter499@users.noreply.github.com",
            "name": "Rafayel Amirkhanyan",
            "username": "Gitter499"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "06169fefedbdc9ffbb090f9d940ed56362e45dfc",
          "message": "Add failing test case for feature #225 (#226)\n\n* feat(#225): Add failing test case\n\n* chore(#225): Remove lengthy explanation and `xb fmt`",
          "timestamp": "2026-06-09T12:09:04-04:00",
          "tree_id": "8e8e751066bea8ae5d25e0194211eca3f54166f5",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/06169fefedbdc9ffbb090f9d940ed56362e45dfc"
        },
        "date": 1781021855215,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.595,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.875,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.62,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.71,
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
          "id": "acb3394fef11b9ea97a96f346e178c6289171a54",
          "message": "Add random shuffling to bytewise copy test (#227)",
          "timestamp": "2026-06-09T18:25:56-04:00",
          "tree_id": "4ca6e6b07c3ad89c3badf7a478d9d2e6f546591f",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/acb3394fef11b9ea97a96f346e178c6289171a54"
        },
        "date": 1781044506966,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.885,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.095,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.82,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.985,
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
          "id": "0880d88e0d527e784c20ced921b4609158e740f6",
          "message": "Rebase again, and bless test output. (#206)",
          "timestamp": "2026-06-09T22:00:01-04:00",
          "tree_id": "804357dc773c117346fe11bf2e734e2171313c8c",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/0880d88e0d527e784c20ced921b4609158e740f6"
        },
        "date": 1781057455909,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.715,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.82,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.64,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.8100000000000005,
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
          "id": "037b387766bac9818539e9932417c1718f58d813",
          "message": "Wildcard Provenance (Part #2) (#218)\n\n* Resolve exposed provenance values for wildcard accesses.\n\n* Add remaining wildcard tests.\n\n* Turn off all debug assertions.\n\n* Fix broken signature from merge.\n\n* fmt\n\n* Eagerly update the frame pointer.",
          "timestamp": "2026-06-10T17:44:19-04:00",
          "tree_id": "a59391ecdba6f013753ea09bd44645bd664d7912",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/037b387766bac9818539e9932417c1718f58d813"
        },
        "date": 1781128362464,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.57,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 4.72,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.71,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 4.78,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          }
        ]
      }
    ]
  }
}