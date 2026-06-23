window.BENCHMARK_DATA = {
  "lastUpdate": 1782239472449,
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
          "id": "783927f37beb7ddd6381ee1f1e05a980a110b26c",
          "message": "Decrement reference count for cleared shadow values (#244)\n\n* feat(#238): decrement reference count for cleared shadow values\n\n* fix(#238): Removed unneccessary `memset` calls\n\n* fix(#238): Readded info_ptr nullification\n\n* fix(#238): Remove tag clearing",
          "timestamp": "2026-06-18T16:32:08-04:00",
          "tree_id": "7ef5e98c159dfe15fb5bfe142389e80e9e9ea10f",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/783927f37beb7ddd6381ee1f1e05a980a110b26c"
        },
        "date": 1781815296936,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.385,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.405,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 8.754999999999999,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 8.785,
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
          "id": "2fa53fe21c21dc24059d0fb61a7efe09954bd08a",
          "message": "Implement `CopyShadow` and `MoveShadow` RC (#247)\n\n* fix(#238): Removed unneccessary `memset` calls\n\n* feat(#238): Added `CopyShadow` and `MoveShadow` implementations\n\n* fix(#238): Ran `xb fmt`\n\n* fix(#238): Implemented fixes",
          "timestamp": "2026-06-19T13:09:55-04:00",
          "tree_id": "e21143a34eb50b8a113ef314bccbba4678b666c3",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/2fa53fe21c21dc24059d0fb61a7efe09954bd08a"
        },
        "date": 1781889575749,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.875,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - aarch64-unknown-linux-gnu",
            "value": 6.97,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\"}"
          },
          {
            "name": "hashbrown@0.17.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 8.96,
            "unit": "Median Relative Execution Time",
            "extra": "{\"mode\": \"nop\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\"}"
          },
          {
            "name": "indexmap@2.14.0 (nop) - x86_64-unknown-linux-gnu",
            "value": 8.925,
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
          "id": "3ddadc70111991c2aa6adcec39bccac2af1fda5e",
          "message": "Merge pull request #243 from BorrowSanitizer/icmccorm/configs\n\nUpdate benchmarking script to add an \"all checks enabled\" mode and compare against Miri",
          "timestamp": "2026-06-19T13:11:19-04:00",
          "tree_id": "b2bdd82b938c2f6af53002b1c7caf880c9637d14",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/3ddadc70111991c2aa6adcec39bccac2af1fda5e"
        },
        "date": 1781889909603,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 784.6796668063954,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 784.6796668063954, \"min\": 784.6796668063954}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.22241503043472957,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.22241503043472957, \"min\": 0.22241503043472957}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.34615353260708537,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.34615353260708537, \"min\": 0.34615353260708537}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 5.949054521508315,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 5.949054521508315, \"min\": 5.949054521508315}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016862411483711882,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0016862411483711882, \"min\": 0.0016862411483711882}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0026243654900265775,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0026243654900265775, \"min\": 0.0026243654900265775}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 1026.9210694033698,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 1026.9210694033698, \"min\": 1026.9210694033698}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.24223607732154986,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.24223607732154986, \"min\": 0.24223607732154986}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.3617445371895214,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.3617445371895214, \"min\": 0.3617445371895214}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 6.612000753134253,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 6.612000753134253, \"min\": 6.612000753134253}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.0015596769541566865,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0015596769541566865, \"min\": 0.0015596769541566865}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.0023291518925879664,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0023291518925879664, \"min\": 0.0023291518925879664}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 864.6374451371126,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 864.6374451371126, \"min\": 864.6374451371126}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2745702464726471,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.2745702464726471, \"min\": 0.2745702464726471}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.4362846391422105,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.4362846391422105, \"min\": 0.4362846391422105}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.426240727581796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 9.426240727581796, \"min\": 9.426240727581796}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0029933531729847895,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0029933531729847895, \"min\": 0.0029933531729847895}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004756356617944616,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004756356617944616, \"min\": 0.004756356617944616}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 971.1324784859993,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 971.1324784859993, \"min\": 971.1324784859993}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.2732504682772972,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.2732504682772972, \"min\": 0.2732504682772972}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.4429061819132972,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.4429061819132972, \"min\": 0.4429061819132972}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 9.234130996613516,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 9.234130996613516, \"min\": 9.234130996613516}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.00259823523036968,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.00259823523036968, \"min\": 0.00259823523036968}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.004211427167355608,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.004211427167355608, \"min\": 0.004211427167355608}"
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
          "id": "007c1c3f02f1fdcf92566abe20aac2aa10f7e58e",
          "message": "Run benchmarks nightly",
          "timestamp": "2026-06-23T10:16:13-04:00",
          "tree_id": "22ee00ca09c6824588549a5a272370afdf7a5d5d",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/007c1c3f02f1fdcf92566abe20aac2aa10f7e58e"
        },
        "date": 1782224973019,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 830.0521172244636,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 830.0521172244636, \"min\": 830.0521172244636}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.21698492092821756,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.21698492092821756, \"min\": 0.21698492092821756}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.32124334674850047,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.32124334674850047, \"min\": 0.32124334674850047}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 6.664648755437693,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 6.664648755437693, \"min\": 6.664648755437693}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017422138359800459,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0017422138359800459, \"min\": 0.0017422138359800459}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0025793248721044685,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025793248721044685, \"min\": 0.0025793248721044685}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 889.1708780056595,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 889.1708780056595, \"min\": 889.1708780056595}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.22404514085013408,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.22404514085013408, \"min\": 0.22404514085013408}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.3277523612409994,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.3277523612409994, \"min\": 0.3277523612409994}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 6.301494866489214,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 6.301494866489214, \"min\": 6.301494866489214}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.0015877930101529782,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0015877930101529782, \"min\": 0.0015877930101529782}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.002322759182658173,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.002322759182658173, \"min\": 0.002322759182658173}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 854.1315778131336,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 854.1315778131336, \"min\": 854.1315778131336}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.23761902899774945,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.23761902899774945, \"min\": 0.23761902899774945}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.3709044283424158,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.3709044283424158, \"min\": 0.3709044283424158}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.757698088272548,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 9.757698088272548, \"min\": 9.757698088272548}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0027145873132626225,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0027145873132626225, \"min\": 0.0027145873132626225}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.004237255155271187,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004237255155271187, \"min\": 0.004237255155271187}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 962.0393434799494,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 962.0393434799494, \"min\": 962.0393434799494}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.2325228662171995,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.2325228662171995, \"min\": 0.2325228662171995}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.35704841410133076,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.35704841410133076, \"min\": 0.35704841410133076}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 9.35598870241532,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 9.35598870241532, \"min\": 9.35598870241532}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.002261322599876279,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.002261322599876279, \"min\": 0.002261322599876279}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.00347235375682635,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.00347235375682635, \"min\": 0.00347235375682635}"
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
          "id": "fae2d2fd66f6e3a3ece478232dfad78f77450d06",
          "message": "Dead list versions of tree GC functions (#245)\n\n* Implemented `RefCount` struct with appropriate endpoints.\n\nTests delivered in [refcount.rs].\n\n* Single-threaded: new starts at 1, increment/decrement/get work as expected, decrement returns true only when hitting zero.\n* Concurrent: 16 threads do balanced inc/dec ops and the count returns to 1. Exactly one thread observes zero on the final decrement. A Release/Acquire test verifies that writes from all threads are visible to the thread that hits zero (Miri catches ordering violations here). Thread counts scale down under cfg!(miri).\n\nResults.\n\n* `cargo test`: 9/9 pass.\n* `cargo miri test`: 9/9 pass, and the three concurrent tests pass across 16 Miri seeds. No ordering violations found.\n\n* edit comment\n\n* Changed  from a regular struct to a tuple struct.\n\n* Added RefCount's to nodes and adjusted several test cases based on the new size of the tree types.\n\n* Added RefCount support for LazyTree Uninit variant.\n\n* Implemented increment and decrement functions for AllocState types.\n\n* Created increment and decrement functions in BorrowTracker.\n\n* Implemented inc/dec functions in lib.rs\n\n* Rust formatting\n\n* Resolved requested changes\n\n* Added dead list versions of the tree GC functions.\n\n* lib.rs inc/dec functions now return true if ref count went from 0 to 1 or dropped to 0 respectively\n\n* formatting\n\n* main declares these as void in bsan_interface_internal.h; the refcount\nwork changed their definitions to return bool, so align the interface\ndeclarations to match and avoid conflicting-types errors when merged.\n\n* Made inc/dec intrinsics void.\n\n---------\n\nCo-authored-by: Ian McCormack <icmccorm@cs.cmu.edu>",
          "timestamp": "2026-06-23T14:18:03-04:00",
          "tree_id": "c935503a800fbb2571d93824345836fa977ac753",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/fae2d2fd66f6e3a3ece478232dfad78f77450d06"
        },
        "date": 1782239471587,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 768.587571465677,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 768.587571465677, \"min\": 768.587571465677}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.21881466910158734,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.21881466910158734, \"min\": 0.21881466910158734}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.32666699224333784,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.32666699224333784, \"min\": 0.32666699224333784}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 5.957270185804911,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 5.957270185804911, \"min\": 5.957270185804911}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.001696017673002231,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.001696017673002231, \"min\": 0.001696017673002231}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0025319737214417153,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0025319737214417153, \"min\": 0.0025319737214417153}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 893.01380560053,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 893.01380560053, \"min\": 893.01380560053}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.22664730048318155,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.22664730048318155, \"min\": 0.22664730048318155}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.3308333254282215,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.3308333254282215, \"min\": 0.3308333254282215}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 6.064265707512688,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 6.064265707512688, \"min\": 6.064265707512688}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.0015391133299402892,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0015391133299402892, \"min\": 0.0015391133299402892}"
          },
          {
            "name": "indexmap@2.14.0 - aarch64-unknown-linux-gnu",
            "value": 0.0022466183363734084,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0022466183363734084, \"min\": 0.0022466183363734084}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 801.0488141785141,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 801.0488141785141, \"min\": 801.0488141785141}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.24089241855080776,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.24089241855080776, \"min\": 0.24089241855080776}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.36942425634770043,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.36942425634770043, \"min\": 0.36942425634770043}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 9.01907756456292,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 9.01907756456292, \"min\": 9.01907756456292}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00271222847992472,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.00271222847992472, \"min\": 0.00271222847992472}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0041593795075369495,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0041593795075369495, \"min\": 0.0041593795075369495}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 922.9634829117351,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 922.9634829117351, \"min\": 922.9634829117351}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.2508664973502227,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.2508664973502227, \"min\": 0.2508664973502227}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.3850750780844363,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.3850750780844363, \"min\": 0.3850750780844363}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 9.195836870893597,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 9.195836870893597, \"min\": 9.195836870893597}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.0024994785045311754,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0024994785045311754, \"min\": 0.0024994785045311754}"
          },
          {
            "name": "indexmap@2.14.0 - x86_64-unknown-linux-gnu",
            "value": 0.0038366497338982283,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-base\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"2.14.0\", \"crate\": \"indexmap\", \"max\": 0.0038366497338982283, \"min\": 0.0038366497338982283}"
          }
        ]
      }
    ]
  }
}