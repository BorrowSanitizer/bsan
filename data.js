window.BENCHMARK_DATA = {
  "lastUpdate": 1782848337308,
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
        "date": 1782532101993,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1563.755849312107,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32244.448682481794, \"min\": 713.4258230500459}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2425698959790828,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.898615159344078, \"min\": 0.06573028722581085}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.3721211445723185,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.365141671660325, \"min\": 6.1349726450716755}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016989510434646722,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002045552541918436, \"min\": 0.0002437933713506126}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1494.9631517939156,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 28807.493554183297, \"min\": 714.9367359594154}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2853559251032534,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9230048181471285, \"min\": 0.07081270625163072}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.93005481291512,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.519108249876496, \"min\": 8.421851637207341}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002948193950052954,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0040094021329215865, \"min\": 0.0006642863684418683}"
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
        "date": 1782619172333,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1588.7103091744411,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33489.84169018238, \"min\": 708.8652022714467}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2418783771265753,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9895642735469539, \"min\": 0.06692460340569642}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.61917721898402,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.24381383133373, \"min\": 6.440702948161859}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017431378300974021,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002126018950185213, \"min\": 0.0002457108628322999}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1538.881895442297,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32538.72419879614, \"min\": 726.5466432805919}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.29209014134791556,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9218972041092142, \"min\": 0.07530585412775008}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.849996749870531,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.19027937640225, \"min\": 8.630635152781407}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.0029556110873111756,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0039413568122224915, \"min\": 0.0006803875335634099}"
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
        "date": 1782705377649,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1509.81484507175,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 27215.130023918788, \"min\": 711.4211292052894}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2404293974490385,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8937419628270433, \"min\": 0.06671997976616686}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.05920133048418,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.40828678354569, \"min\": 5.634140388099777}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016340859587774433,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.001990358883487194, \"min\": 0.00024168920090512257}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1511.7045129446751,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 32592.308168239637, \"min\": 702.7261383307278}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.26539909994776767,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9154895479008691, \"min\": 0.06955180279841416}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.673099012009354,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.589580942829926, \"min\": 8.044107232130825}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002725444715723371,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003697558328743631, \"min\": 0.0006768255632071954}"
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
        "date": 1782791721644,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1647.819980129921,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 40620.05835345409, \"min\": 753.9590755687428}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2404676429095912,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8737313830136947, \"min\": 0.06441388744330966}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.80217620832785,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.25073103537164, \"min\": 6.738664949021367}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017761390914114944,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002144421269492113, \"min\": 0.00024822118781869}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1423.2428386959853,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 30249.620722180112, \"min\": 722.9777026492068}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2881568335209116,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9068945984949682, \"min\": 0.0745460931887799}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.818021519604796,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.41164157791656, \"min\": 8.185734435854078}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.00295453632301958,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0038196684199342853, \"min\": 0.0006535070125178928}"
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
          "id": "ee02764e9a352d2f5362f9d40dfb3e1396b27aff",
          "message": "Ignored .patch, updated dependencies. (#260)",
          "timestamp": "2026-06-30T11:06:48-04:00",
          "tree_id": "7efc3a4c5e34535c18542cd2708dbff8e9627da6",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/ee02764e9a352d2f5362f9d40dfb3e1396b27aff"
        },
        "date": 1782837042541,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1539.0142531031076,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31987.464909083425, \"min\": 718.7488792238004}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23936637710209036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8659121395452318, \"min\": 0.06527490644246826}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.521846501233942,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 16.148347547383032, \"min\": 6.323523546531507}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0017539057277441703,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002148542972748216, \"min\": 0.00024166337161137002}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1432.2646228084345,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 20911.675544873655, \"min\": 678.3096157539974}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2809555811512036,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9049213813532707, \"min\": 0.0729395421463255}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 11.153569766373993,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 37.23249685887956, \"min\": 8.449645128506887}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002945001726875964,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.004208788344699682, \"min\": 0.000659500604201373}"
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
          "id": "4dd3e908130786dcafabbe2e4025fbf58d13d213",
          "message": "Fail gracefully when shadow memory reservation fails (#262)",
          "timestamp": "2026-06-30T11:34:00-04:00",
          "tree_id": "2937f208cc8f7223533843eb2e5c8e6b76a5baa9",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/4dd3e908130786dcafabbe2e4025fbf58d13d213"
        },
        "date": 1782841928690,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1557.3524572115896,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 33993.45054054116, \"min\": 626.2207094038367}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.23741261976601186,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.894922193334424, \"min\": 0.06495705692983693}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.652209714754299,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.409814218458301, \"min\": 5.4354305670252865}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.001769784696671965,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.0022151648495792246, \"min\": 0.00023693167156823872}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1485.824521724856,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 28097.311401862004, \"min\": 713.144035629078}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2852137097546972,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8782519532881088, \"min\": 0.07377750961896581}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.92788493096392,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.96948204557039, \"min\": 8.385088592342587}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002938103184418046,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003947129805441583, \"min\": 0.0006715567728559626}"
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
            "email": "icmccorm@cs.cmu.edu",
            "name": "Ian McCormack",
            "username": "icmccorm"
          },
          "distinct": true,
          "id": "37ee2e15ad12066ca6bd4bf165f468e0db531e9d",
          "message": "Remove and .gitignore .idea.",
          "timestamp": "2026-06-30T14:20:52-04:00",
          "tree_id": "5abdce579a30a632b39b6ecde6e9d3af70f460b9",
          "url": "https://github.com/BorrowSanitizer/bsan/commit/37ee2e15ad12066ca6bd4bf165f468e0db531e9d"
        },
        "date": 1782848336019,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 1577.7075863742612,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 35216.60016542916, \"min\": 709.38547546242}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.2406660232076306,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.8842511035199614, \"min\": 0.06630774648105138}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 7.178462264689976,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 15.589088979726338, \"min\": 5.996835056134633}"
          },
          {
            "name": "hashbrown@0.17.0 - aarch64-unknown-linux-gnu",
            "value": 0.0016701162506986748,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"aarch64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.002099363994002555, \"min\": 0.00024021989387104504}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 1526.5654177822626,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 31806.67392276901, \"min\": 698.2260313719352}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.2655552754565187,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"full\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.9132911068523648, \"min\": 0.06979085984693577}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 10.961409831972965,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"native\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 36.14217562216035, \"min\": 7.95876135117046}"
          },
          {
            "name": "hashbrown@0.17.0 - x86_64-unknown-linux-gnu",
            "value": 0.002742282860087224,
            "unit": "Mean Relative Execution Time",
            "extra": "{\"mode\": \"no-op\", \"baseline\": \"miri-tb\", \"target\": \"x86_64-unknown-linux-gnu\", \"version\": \"0.17.0\", \"crate\": \"hashbrown\", \"max\": 0.003620048705473489, \"min\": 0.000664912745092868}"
          }
        ]
      }
    ]
  }
}