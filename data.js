window.BENCHMARK_DATA = {
  "lastUpdate": 1779385008402,
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
          "id": "98f985c1ef439ea71a47104537b1b9dcffa5c5d4",
          "message": "Move fields into extra.",
          "timestamp": "2026-05-18T13:58:03Z",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/98f985c1ef439ea71a47104537b1b9dcffa5c5d4"
        },
        "date": 1779383319561,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 5.6986623481853425,
            "unit": "Median Relative Execution Time",
            "extra": "[object Object]"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 5.862688720775822,
            "unit": "Median Relative Execution Time",
            "extra": "[object Object]"
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
      }
    ]
  }
}